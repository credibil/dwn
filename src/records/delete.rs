//! # Delete
//!
//! `Delete` is a message type used to delete a record in the web node.

use std::cmp::Ordering;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Context, Message, MessageRecord, MessageType, Reply, Status};
use crate::event::Event;
use crate::permissions::{self, protocol};
use crate::provider::{EventLog, EventStream, MessageStore, Provider, Signer};
use crate::records::Write;
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
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND recordId = '{record_id}'
        AND queryable = true
        ORDER BY descriptor.messageTimestamp DESC
        ",
        interface = Interface::Records,
        record_id = delete.descriptor.record_id,
    );
    let (messages, _) = MessageStore::query(provider, owner, &sql).await?;
    if messages.is_empty() {
        return Err(Error::NotFound("no matching records found".to_string()));
    }

    if messages[0].descriptor().method == Method::Delete {
        return Err(Error::NotFound("no matching records found".to_string()));
    }

    delete.authorize(owner, &Write::try_from(&messages[0])?, provider).await?;
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

impl TryFrom<MessageRecord> for Delete {
    type Error = crate::Error;

    fn try_from(record: MessageRecord) -> Result<Self> {
        match record.message {
            MessageType::RecordsDelete(delete) => Ok(delete),
            _ => Err(unexpected!("expected `RecordsDelete` message")),
        }
    }
}

impl TryFrom<&MessageRecord> for Delete {
    type Error = crate::Error;

    fn try_from(record: &MessageRecord) -> Result<Self> {
        match &record.message {
            MessageType::RecordsDelete(delete) => Ok(delete.clone()),
            _ => Err(unexpected!("expected `RecordsDelete` message")),
        }
    }
}

impl From<&Delete> for MessageRecord {
    fn from(delete: &Delete) -> Self {
        let mut record = Self {
            message: MessageType::RecordsDelete(delete.clone()),
            indexes: Map::new(),
        };

        // indexes
        record
            .indexes
            .insert("recordId".to_string(), Value::String(delete.descriptor.record_id.clone()));
        record.indexes.insert("queryable".to_string(), Value::Bool(true));

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
            let grant = permissions::Grant::try_from(delegated_grant)?;
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
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND recordId = '{record_id}'
        ORDER BY descriptor.messageTimestamp DESC
        ",
        interface = Interface::Records,
        record_id = delete.descriptor.record_id,
    );

    let (messages, _) = MessageStore::query(provider, owner, &sql).await?;
    if messages.is_empty() {
        return Err(Error::NotFound("no matching records found".to_string()));
    }
    if messages.len() > 2 {
        return Err(unexpected!("multiple messages exist for the RecordsDelete filter"));
    }
    let newest_existing = &messages[0];
    let method = &newest_existing.descriptor().method;

    if method == &Method::Delete {
        // cannot delete a `RecordsDelete` record
        if !delete.descriptor.prune {
            return Err(Error::NotFound("cannot delete a RecordsDelete record".to_string()));
        }

        // fail when existing `RecordsDelete` has `prune` set
        let existing_delete = Delete::try_from(newest_existing)?;
        if existing_delete.descriptor.prune {
            return Err(Error::NotFound(
                "attempting to prune an already pruned record".to_string(),
            ));
        }
    }

    // TODO: merge this code with `RecordsWrite`
    // if the incoming message is not the newest, return Conflict
    let delete_ts = delete.descriptor().message_timestamp.unwrap_or_default();
    let latest_ts = newest_existing.descriptor().message_timestamp.unwrap_or_default();
    if delete_ts.cmp(&latest_ts) == Ordering::Less {
        return Err(Error::Conflict("newer record already exists".to_string()));
    }

    let Some(earliest) = messages.last() else {
        return Err(unexpected!("no messages found"));
    };
    let write = Write::try_from(earliest)?;

    if !write.is_initial()? {
        return Err(unexpected!("initial write is not earliest message"));
    }

    // save the delete message using same indexes as the initial write
    let initial = MessageRecord::from(&write);
    let mut record = MessageRecord::from(delete);
    record.indexes.extend(initial.indexes);
    MessageStore::put(provider, owner, &record).await?;

    let event = Event {
        message_cid: delete.cid()?,
        base: delete.descriptor.base.clone(),
        protocol: write.descriptor.protocol.clone(),
    };
    EventLog::append(provider, owner, &event).await?;
    EventStream::emit(provider, owner, &event).await?;

    // purge/hard-delete all descendent records
    if delete.descriptor.prune {
        // await StorageController.purgeRecordDescendants(tenant, message.descriptor.recordId, this.messageStore, this.dataStore, this.eventLog);
    }

    // delete all existing messages that are not newest, except for the initial write
    //     await StorageController.deleteAllOlderMessagesButKeepInitialWrite(
    //       tenant, existingMessages, message, this.messageStore, this.dataStore, this.eventLog
    //     );
    //   }

    Ok(())
}
