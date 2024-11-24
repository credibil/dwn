//! # Delete
//!
//! `Delete` is a message type used to delete a record in the web node.

use std::cmp::Ordering;
use std::collections::HashMap;

use async_recursion::async_recursion;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Context, Message, Reply, Status};
use crate::permissions::protocol;
use crate::provider::{BlockStore, EventLog, EventStream, MessageStore, Provider, Signer};
use crate::records::Write;
use crate::store::{Entry, EntryType, RecordsQuery};
use crate::tasks::{self, Task, TaskType};
use crate::{unexpected, Descriptor, Error, Interface, Method, Result};

/// Process `Delete` message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    owner: &str, delete: Delete, provider: &impl Provider,
) -> Result<Reply<DeleteReply>> {
    // a `RecordsWrite` record is required for delete processing

    let query = RecordsQuery::new().record_id(&delete.descriptor.record_id).method(None).build();
    let (records, _) = MessageStore::query(provider, owner, &query).await?;
    if records.is_empty() {
        return Err(Error::NotFound("no matching records found".to_string()));
    }

    // run checks when latest existing message is a `RecordsDelete`
    let newest_existing = &records[0];
    if newest_existing.descriptor().method == Method::Delete {
        // cannot delete a `RecordsDelete` record
        if !delete.descriptor.prune {
            return Err(Error::NotFound("cannot delete a `RecordsDelete` record".to_string()));
        }

        // cannot prune previously pruned record
        let existing_delete = Delete::try_from(newest_existing)?;
        if existing_delete.descriptor.prune {
            return Err(Error::NotFound(
                "attempting to prune an already pruned record".to_string(),
            ));
        }
    }

    delete.authorize(owner, &Write::try_from(&records[0])?, provider).await?;
    tasks::run(owner, TaskType::RecordsDelete(delete.clone()), provider).await?;

    Ok(Reply {
        status: Status {
            code: StatusCode::ACCEPTED.as_u16(),
            detail: None,
        },
        body: None,
    })
}

/// Records delete message payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delete {
    /// Delete descriptor.
    pub descriptor: DeleteDescriptor,

    /// Message authorization.
    pub authorization: Authorization,
}

#[async_trait]
impl Message for Delete {
    type Reply = DeleteReply;

    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }

    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(&ctx.owner, self, provider).await
    }
}

/// Delete reply.
#[derive(Debug)]
pub struct DeleteReply;

impl TryFrom<Entry> for Delete {
    type Error = crate::Error;

    fn try_from(record: Entry) -> Result<Self> {
        match record.message {
            EntryType::Delete(delete) => Ok(delete),
            _ => Err(unexpected!("expected `RecordsDelete` message")),
        }
    }
}

impl TryFrom<&Entry> for Delete {
    type Error = crate::Error;

    fn try_from(record: &Entry) -> Result<Self> {
        match &record.message {
            EntryType::Delete(delete) => Ok(delete.clone()),
            _ => Err(unexpected!("expected `RecordsDelete` message")),
        }
    }
}

impl From<&Delete> for Entry {
    fn from(delete: &Delete) -> Self {
        let mut record = Self {
            message: EntryType::Delete(delete.clone()),
            indexes: Map::new(),
        };

        // flatten record_id so it queries correctly
        record
            .indexes
            .insert("recordId".to_string(), Value::String(delete.descriptor.record_id.clone()));
        record.indexes.insert("archived".to_string(), Value::Bool(false));

        record
    }
}

#[async_trait]
impl Task for Delete {
    async fn run(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        delete(owner, self, provider).await
    }
}

impl Delete {
    /// Authorize the delete message.
    async fn authorize(&self, owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = &authzn.author()?;

        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant = delegated_grant.to_grant()?;
            grant.permit_delete(author, &authzn.signer()?, self, write, store).await?;
        };

        if author == owner {
            return Ok(());
        }

        if write.descriptor.protocol.is_some() {
            return protocol::permit_delete(owner, self, write, store).await;
        }

        Err(Error::Unauthorized("`RecordsDelete` message failed authorization".to_string()))
    }
}

/// Deletes delete descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The ID of the record to delete.
    pub record_id: String,

    /// Specifies whether descendent records should be pruned or not.
    pub prune: bool,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct DeleteBuilder {
    record_id: Option<String>,
    prune: Option<bool>,
    message_timestamp: Option<DateTime<Utc>>,
    permission_grant_id: Option<String>,
}

impl DeleteBuilder {
    /// Returns a new [`DeleteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        // set defaults
        Self {
            message_timestamp: Some(now),
            ..Self::default()
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub const fn prune(mut self, prune: bool) -> Self {
        self.prune = Some(prune);
        self
    }

    /// The datetime the record was created. Defaults to now.
    #[must_use]
    pub const fn message_timestamp(mut self, message_timestamp: DateTime<Utc>) -> Self {
        self.message_timestamp = Some(message_timestamp);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Build the write message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Delete> {
        let Some(record_id) = self.record_id else {
            return Err(unexpected!("`record_id` is not set"));
        };

        let descriptor = DeleteDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Delete,
                message_timestamp: self.message_timestamp,
            },
            record_id,
            prune: self.prune.unwrap_or(false),
        };

        let mut auth_builder =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            auth_builder = auth_builder.permission_grant_id(id);
        }
        let authorization = auth_builder.build(signer).await?;

        Ok(Delete {
            descriptor,
            authorization,
        })
    }
}

pub(crate) async fn delete(owner: &str, delete: &Delete, provider: &impl Provider) -> Result<()> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let query = RecordsQuery::new()
        .record_id(&delete.descriptor.record_id)
        .method(None)
        .archived(None)
        .build();
    let (records, _) = MessageStore::query(provider, owner, &query).await?;
    if records.is_empty() {
        return Err(Error::NotFound("no matching records found".to_string()));
    }
    if records.len() > 2 {
        return Err(unexpected!("multiple messages exist"));
    }

    let newest_existing = &records[0];

    // TODO: merge this code with `RecordsWrite`
    // if the incoming message is not the newest, return Conflict
    let delete_ts = delete.descriptor().message_timestamp.unwrap_or_default();
    let latest_ts = newest_existing.descriptor().message_timestamp.unwrap_or_default();
    if delete_ts.cmp(&latest_ts) == Ordering::Less {
        return Err(Error::Conflict("newer record already exists".to_string()));
    }

    let Some(earliest) = records.last() else {
        return Err(unexpected!("no records found"));
    };

    let write = Write::try_from(earliest)?;
    if !write.is_initial()? {
        return Err(unexpected!("initial write is not earliest message"));
    }

    // save the delete message using same indexes as the initial write
    let initial = Entry::from(&write);
    let mut entry = Entry::from(delete);
    entry.indexes.extend(initial.indexes);
    MessageStore::put(provider, owner, &entry).await?;
    EventLog::append(provider, owner, &entry).await?;
    EventStream::emit(provider, owner, &entry).await?;

    // purge/hard-delete all descendent records
    if delete.descriptor.prune {
        delete_children(owner, &delete.descriptor.record_id, provider).await?;
    }

    // delete all messages except initial write and most recent
    delete_earlier(owner, &Entry::from(delete), &records, provider).await?;

    Ok(())
}

// Purge a record's descendant records and data.
#[async_recursion]
async fn delete_children(owner: &str, record_id: &str, provider: &impl Provider) -> Result<()> {
    // fetch child records
    let query = RecordsQuery::new().parent_id(record_id).build();
    let (children, _) = MessageStore::query(provider, owner, &query).await?;
    if children.is_empty() {
        return Ok(());
    }

    // group by `record_id` (a record can have multiple children)
    let mut record_id_map = HashMap::<&str, Vec<Entry>>::new();
    for message in children {
        let record_id = if let Some(write) = message.as_write() {
            &write.record_id
        } else {
            let Some(delete) = message.as_delete() else {
                return Err(unexpected!("unexpected message type"));
            };
            &delete.descriptor.record_id
        };

        record_id_map
            .get_mut(record_id.as_str())
            .unwrap_or(&mut Vec::<Entry>::new())
            .push(message.clone());
    }

    for (record_id, messages) in record_id_map {
        // purge child's descendants
        delete_children(owner, record_id, provider).await?;
        // purge child's messages
        purge(owner, &messages, provider).await?;
    }

    Ok(())
}

// Purge record's specified records and data.
async fn purge(owner: &str, records: &[Entry], provider: &impl Provider) -> Result<()> {
    // filter out `RecordsDelete` messages
    let mut writes =
        records.iter().filter(|m| m.descriptor().method == Method::Write).collect::<Vec<&Entry>>();

    // order records from earliest to most recent
    writes.sort_by(|a, b| {
        let ts_a = a.descriptor().message_timestamp.unwrap_or_default();
        let ts_b = b.descriptor().message_timestamp.unwrap_or_default();
        ts_a.cmp(&ts_b)
    });

    // delete data for the most recent write
    let Some(latest) = writes.pop() else {
        return Ok(());
    };
    let Some(write) = latest.as_write() else {
        return Err(unexpected!("latest record is not a `RecordsWrite`"));
    };
    BlockStore::delete(provider, owner, &write.descriptor.data_cid).await?;

    // delete message events
    for message in records {
        let cid = message.cid()?;
        EventLog::delete(provider, owner, &cid).await?;
        MessageStore::delete(provider, owner, &cid).await?;
    }

    Ok(())
}

// Deletes all messages in `existing` that are older than the `newest` in the
// given tenant, but keep the initial write write for future processing by
// ensuring its `private` index is "true".
async fn delete_earlier(
    owner: &str, newest: &Entry, existing: &[Entry], provider: &impl Provider,
) -> Result<()> {
    // N.B. under normal circumstances, there will only be, at most, two existing
    // records per `record_id` (initial + a potential subsequent write/delete),
    for message in existing {
        let ts_message = message.descriptor().message_timestamp.unwrap_or_default();
        let ts_newest = newest.descriptor().message_timestamp.unwrap_or_default();

        if ts_message.cmp(&ts_newest) == Ordering::Less {
            delete_data(owner, message, newest, provider).await?;
            MessageStore::delete(provider, owner, &message.cid()?).await?;

            // when the existing message is the initial write, retain it BUT,
            // ensure the message is marked as `archived`
            if let Some(write) = message.as_write()
                && write.is_initial()?
            {
                let mut record = Entry::from(write);
                record.indexes.insert("archived".to_string(), Value::Bool(true));
                MessageStore::put(provider, owner, &record).await?;
            } else {
                EventLog::delete(provider, owner, &message.cid()?).await?;
            }
        }
    }

    Ok(())
}

// Deletes the data referenced by the given message if needed.
async fn delete_data(
    owner: &str, existing: &Entry, newest: &Entry, store: &impl BlockStore,
) -> Result<()> {
    let Some(existing_write) = existing.as_write() else {
        return Err(unexpected!("unexpected message type"));
    };

    // keep data if referenced by newest message
    if let Some(newest_write) = newest.as_write() {
        if existing_write.descriptor.data_cid == newest_write.descriptor.data_cid {
            return Ok(());
        }
    };

    // // short-circuit when data is encoded in message (i.e. not in block store)
    // if write.descriptor.data_size <= data::MAX_ENCODED_SIZE {
    //     return Ok(());
    // }

    BlockStore::delete(store, owner, &existing_write.descriptor.data_cid)
        .await
        .map_err(|e| unexpected!("failed to delete data: {e}"))
}
