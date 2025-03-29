//! # Records Delete
//!
//! The documents delete endpoint handles `RecordsDelete` messages — requests
//! to delete a [`Write`] record.
//!
//! Technically, the [`Write`] record is not deleted, but rather a new
//! [`Delete`] record is created to mark the record as deleted. The [`Delete`]
//! record is used to prune the record and its descendants from the system,
//! leaving only the [`Delete`] and initial [`Write`] documents.

use std::collections::HashMap;

use async_recursion::async_recursion;
use chrono::SecondsFormat::Micros;
use http::StatusCode;

use crate::endpoint::{Reply, ReplyBody, Status};
use crate::handlers::verify_protocol;
use crate::interfaces::Document;
use crate::interfaces::records::{Delete, RecordsFilter, Write};
use crate::provider::{DataStore, EventLog, EventStream, MessageStore, Provider};
use crate::store::{RecordsQueryBuilder, Storable};
use crate::tasks::{self, Task, TaskType};
use crate::{Error, Interface, Method, Result, bad, forbidden};

/// Handle — or process — a [`Delete`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to delete the specified record from the
/// [`MessageStore`].
pub async fn handle(
    owner: &str, delete: Delete, provider: &impl Provider,
) -> Result<Reply<ReplyBody>> {
    // a `RecordsWrite` record is required for delete processing
    let query = RecordsQueryBuilder::new()
        .method(None)
        .add_filter(RecordsFilter::new().record_id(&delete.descriptor.record_id))
        .build();
    let (entries, _) = MessageStore::query(provider, owner, &query).await?;
    if entries.is_empty() {
        return Err(Error::NotFound("no matching record found".to_string()));
    }
    let latest = &entries[0];

    // check the latest existing message has not already been deleted
    if latest.descriptor().method == Method::Delete {
        // cannot delete a `RecordsDelete` record
        if !delete.descriptor.prune {
            return Err(Error::NotFound("cannot delete a `RecordsDelete` record".to_string()));
        }

        // cannot prune previously pruned record
        let existing_delete = Delete::try_from(latest)?;
        if existing_delete.descriptor.prune {
            return Err(Error::NotFound(
                "attempting to prune an already pruned record".to_string(),
            ));
        }
    }

    // authorize the delete message
    delete.authorize(owner, &Write::try_from(latest)?, provider).await?;

    // ensure the delete request does not pre-date the latest existing version
    if delete.descriptor.base.message_timestamp.timestamp_micros()
        < latest.descriptor().message_timestamp.timestamp_micros()
    {
        return Err(Error::Conflict("newer record version exists".to_string()));
    }

    // run the delete task as a resumable task
    tasks::run(owner, TaskType::RecordsDelete(delete.clone()), provider).await?;

    Ok(Reply {
        status: Status {
            code: StatusCode::ACCEPTED.as_u16(),
            detail: None,
        },
        body: None,
    })
}

impl Storable for Delete {
    fn document(&self) -> impl crate::store::Document {
        Document::Delete(self.clone())
    }

    fn indexes(&self) -> HashMap<String, String> {
        let mut indexes = self.indexes.clone();
        indexes.extend(self.build_indexes());
        indexes
    }

    fn add_index(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.indexes.insert(key.into(), value.into());
    }
}

impl TryFrom<Document> for Delete {
    type Error = crate::Error;

    fn try_from(document: Document) -> Result<Self> {
        match document {
            Document::Delete(delete) => Ok(delete),
            _ => Err(bad!("expected `RecordsDelete` message")),
        }
    }
}

impl TryFrom<&Document> for Delete {
    type Error = crate::Error;

    fn try_from(document: &Document) -> Result<Self> {
        match document {
            Document::Delete(delete) => Ok(delete.clone()),
            _ => Err(bad!("expected `RecordsDelete` message")),
        }
    }
}

impl Task for Delete {
    async fn run(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        delete(owner, self, provider).await
    }
}

impl Delete {
    /// Build flattened indexes for the write message.
    #[must_use]
    pub(crate) fn build_indexes(&self) -> HashMap<String, String> {
        let mut indexes = HashMap::new();
        indexes.insert("interface".to_string(), Interface::Records.to_string());
        indexes.insert("method".to_string(), Method::Delete.to_string());
        indexes.insert("recordId".to_string(), self.descriptor.record_id.clone());
        indexes.insert(
            "messageTimestamp".to_string(),
            self.descriptor.base.message_timestamp.to_rfc3339_opts(Micros, true),
        );
        indexes.insert("author".to_string(), self.authorization.author().unwrap_or_default());
        indexes.insert("initial".to_string(), "false".to_string());
        indexes
    }

    /// Authorize the delete message.
    async fn authorize(&self, owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = &authzn.author()?;

        // when signed by delegate, authorize delegate
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant = delegated_grant.to_grant()?;
            grant.permit_delete(author, &authzn.signer()?, self, write, store).await?;
        }

        if author == owner {
            return Ok(());
        }

        if let Some(protocol) = &write.descriptor.protocol {
            let protocol = verify_protocol::Authorizer::new(protocol)
                .context_id(write.context_id.as_ref())
                .initial_write(write);
            return protocol.permit_delete(owner, self, store).await;
        }

        Err(forbidden!("delete request failed authorization"))
    }
}

async fn delete(owner: &str, delete: &Delete, provider: &impl Provider) -> Result<()> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let query = RecordsQueryBuilder::new()
        .method(None)
        .include_archived(true)
        .add_filter(RecordsFilter::new().record_id(&delete.descriptor.record_id))
        .build();

    let (entries, _) = MessageStore::query(provider, owner, &query).await?;
    if entries.is_empty() {
        return Err(Error::NotFound("no matching documents found".to_string()));
    }
    if entries.len() > 2 {
        return Err(bad!("multiple messages exist"));
    }

    // delete message should be the most recent message
    let latest = &entries[entries.len() - 1];
    if delete.descriptor.base.message_timestamp < latest.descriptor().message_timestamp {
        return Err(Error::Conflict("newer record already exists".to_string()));
    }

    // this should be the initial write
    let write = Write::try_from(&entries[0])?;
    if !write.is_initial()? {
        return Err(bad!("initial write is not earliest message"));
    }

    // ensure the `RecordsDelete` message is searchable
    let mut delete = delete.clone();
    for (key, value) in write.build_indexes() {
        delete.add_index(key, value);
    }

    MessageStore::put(provider, owner, &delete).await?;
    EventLog::append(provider, owner, &delete).await?;
    EventStream::emit(provider, owner, &Document::Delete(delete.clone())).await?;

    // purge/hard-delete all descendent documents
    if delete.descriptor.prune {
        delete_children(owner, &delete.descriptor.record_id, provider).await?;
    }

    // delete all messages except initial write and most recent
    delete_earlier(owner, &Document::Delete(delete.clone()), &entries, provider).await?;

    Ok(())
}

// Purge a record's descendant documents and data.
#[async_recursion]
async fn delete_children(owner: &str, record_id: &str, provider: &impl Provider) -> Result<()> {
    // fetch child documents
    let query =
        RecordsQueryBuilder::new().add_filter(RecordsFilter::new().parent_id(record_id)).build();
    let (children, _) = MessageStore::query(provider, owner, &query).await?;
    if children.is_empty() {
        return Ok(());
    }

    // group by `record_id` (a record can have multiple children)
    let mut record_id_map = HashMap::<&str, Vec<Document>>::new();
    for document in children {
        let record_id = if let Some(write) = document.as_write() {
            &write.record_id
        } else {
            let Some(delete) = document.as_delete() else {
                return Err(bad!("unexpected message type"));
            };
            &delete.descriptor.record_id
        };

        record_id_map
            .get_mut(record_id.as_str())
            .unwrap_or(&mut Vec::<Document>::new())
            .push(document.clone());
    }

    for (record_id, entries) in record_id_map {
        // purge child's descendants
        delete_children(owner, record_id, provider).await?;
        // purge child's entries
        purge(owner, &entries, provider).await?;
    }

    Ok(())
}

// Purge record's specified documents and data.
async fn purge(owner: &str, documents: &[Document], provider: &impl Provider) -> Result<()> {
    // filter out `RecordsDelete` messages
    let mut writes = documents
        .iter()
        .filter(|m| m.descriptor().method == Method::Write)
        .collect::<Vec<&Document>>();

    // order documents from earliest to most recent
    writes.sort_by(|a, b| a.descriptor().message_timestamp.cmp(&b.descriptor().message_timestamp));

    // delete data for the most recent write
    let Some(latest) = writes.pop() else {
        return Ok(());
    };
    let Some(write) = latest.as_write() else {
        return Err(bad!("latest record is not a `RecordsWrite`"));
    };
    DataStore::delete(provider, owner, &write.record_id, &write.descriptor.data_cid).await?;

    // delete message events
    for message in documents {
        let cid = message.cid()?;
        EventLog::delete(provider, owner, &cid).await?;
        MessageStore::delete(provider, owner, &cid).await?;
    }

    Ok(())
}

// Deletes all messages in `existing` that are older than the `latest` in the
// given tenant, but keep the initial write write for future processing by
// ensuring its `private` index is "true".
async fn delete_earlier(
    owner: &str, latest: &Document, existing: &[Document], provider: &impl Provider,
) -> Result<()> {
    // N.B. typically there will only be, at most, two existing documents per
    // `record_id` (initial + a potential subsequent write/delete),
    for document in existing {
        if document.descriptor().message_timestamp < latest.descriptor().message_timestamp {
            delete_data(owner, document, latest, provider).await?;

            // when the existing message is the initial write, retain it BUT,
            // ensure the message is marked as `archived`
            let mut write = Write::try_from(document)?;
            if write.is_initial()? {
                write.add_index("initial", true.to_string());
                MessageStore::put(provider, owner, &write).await?;
            } else {
                let cid = document.cid()?;
                MessageStore::delete(provider, owner, &cid).await?;
                EventLog::delete(provider, owner, &cid).await?;
            }
        }
    }

    Ok(())
}

// Deletes the data referenced by the given message if needed.
async fn delete_data(
    owner: &str, existing: &Document, latest: &Document, store: &impl DataStore,
) -> Result<()> {
    let Some(existing_write) = existing.as_write() else {
        return Err(bad!("unexpected message type"));
    };

    // keep data if referenced by latest message
    if let Some(latest_write) = latest.as_write() {
        if existing_write.descriptor.data_cid == latest_write.descriptor.data_cid {
            return Ok(());
        }
    }

    // // short-circuit when data is encoded in message (i.e. not in block store)
    // if write.descriptor.data_size <= data::MAX_ENCODED_SIZE {
    //     return Ok(());
    // }

    DataStore::delete(store, owner, &existing_write.record_id, &existing_write.descriptor.data_cid)
        .await
        .map_err(|e| bad!("failed to delete data: {e}"))
}
