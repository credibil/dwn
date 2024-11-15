//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::fmt::Debug;
use std::ops::Deref;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::auth::Authorization;
use crate::permissions::{self, Grant};
use crate::provider::Provider;
use crate::{messages, protocols, records, schema, unexpected, Descriptor, Error, Result};

/// Handle incoming messages.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(owner: &str, message: impl Message, provider: &impl Provider) -> Result<Reply> {
    let mut ctx = Context::new(owner);
    message.validate(&mut ctx, provider).await?;
    message.handle(&mut ctx, provider).await
}

/// Methods common to all messages.
#[async_trait]
pub trait Message: Serialize + Clone + Debug + Send + Sync {
    /// Compute the CID of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    fn cid(&self) -> Result<String>;

    /// Returns the component of the message descriptor common to all messages
    fn descriptor(&self) -> &Descriptor;

    /// Returns the messages's authorization, if set.
    fn authorization(&self) -> Option<&Authorization>;

    /// Handle the message.
    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply>;

    /// Validate the message. This is a generic validation common to all messages.
    /// Message-specific validation is done in the message handler.
    async fn validate(&self, ctx: &mut Context, provider: &impl Provider) -> Result<()> {
        // if !tenant_gate.active(owner)? {
        //     return Err(Error::Unauthorized("tenant not active"));
        // }

        schema::validate(self)?;

        // message has no authorization
        let Some(authzn) = self.authorization() else {
            return Ok(());
        };

        // authenticate the message
        if let Err(e) = authzn.authenticate(provider).await {
            return Err(Error::Unauthorized(format!("failed to authenticate message: {e}")));
        }

        // no checks needed when message author is web node owner
        let author = authzn.author()?;
        if author == ctx.owner {
            return Ok(());
        }

        // verify the permission grant
        let payload = authzn.jws_payload()?;
        let Some(grant_id) = &payload.permission_grant_id else {
            return Err(unexpected!("`permission_grant_id` not found in signature payload",));
        };
        let grant = permissions::fetch_grant(&ctx.owner, grant_id, provider).await?;
        grant.verify(&author, &authzn.signer()?, self.descriptor(), provider).await?;
        ctx.grant = Some(grant);

        Ok(())
    }
}

/// Reply used by all endpoints.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Reply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// Endpoint-specific reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub reply: Option<ReplyType>,
}

impl Reply {
    /// Surface the underlying `RecordsRead` reply.
    #[must_use]
    pub fn records_read(self) -> Option<records::ReadReply> {
        match self.reply {
            Some(ReplyType::RecordsRead(reply)) => Some(reply),
            _ => None,
        }
    }

    /// Surface the underlying `MessagesQuery` reply.
    #[must_use]
    pub fn messages_query(self) -> Option<messages::QueryReply> {
        match self.reply {
            Some(ReplyType::MessagesQuery(reply)) => Some(reply),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum ReplyType {
    MessagesQuery(messages::QueryReply),
    MessagesRead(messages::ReadReply),
    MessagesSubscribe(messages::SubscribeReply),
    ProtocolsConfigure(protocols::ConfigureReply),
    ProtocolsQuery(protocols::QueryReply),
    RecordsRead(records::ReadReply),
    // RecordsWrite(records::WriteReply),
}

/// Reply status.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Status code.
    pub code: u16,

    /// Status detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Wraps each message with a unifying type used in operations common to all
/// messages. For example, storing and retrieving from the `MessageStore`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageRecord {
    /// The message type.
    #[serde(flatten)]
    pub message: MessageType,

    /// Indexed message object fields, flattened for querying.
    #[serde(flatten)]
    pub indexes: Map<String, Value>,
}

impl MessageRecord {
    /// The message's CID.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn cid(&self) -> Result<String> {
        match self.message {
            MessageType::RecordsWrite(ref write) => write.cid(),
            MessageType::ProtocolsConfigure(ref configure) => configure.cid(),
        }
    }

    /// The message's CID.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor {
        match self.message {
            MessageType::RecordsWrite(ref write) => write.descriptor(),
            MessageType::ProtocolsConfigure(ref configure) => configure.descriptor(),
        }
    }
}

impl MessageRecord {
    /// Return the `RecordsWrite` message, if set.
    #[must_use]
    pub const fn as_write(&self) -> Option<&records::Write> {
        match &self.message {
            MessageType::RecordsWrite(write) => Some(write),
            MessageType::ProtocolsConfigure(_) => None,
        }
    }

    /// Return the `ProtocolsConfigure` message, if set.
    #[must_use]
    pub const fn as_configure(&self) -> Option<&protocols::Configure> {
        match &self.message {
            MessageType::ProtocolsConfigure(configure) => Some(configure),
            MessageType::RecordsWrite(_) => None,
        }
    }
}

impl Deref for MessageRecord {
    type Target = MessageType;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// Records read message payload
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[allow(missing_docs)]
pub enum MessageType {
    RecordsWrite(records::Write),
    ProtocolsConfigure(protocols::Configure),
}

impl Default for MessageType {
    fn default() -> Self {
        Self::RecordsWrite(records::Write::default())
    }
}

/// Message context for attaching information used during processing.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The web node owner (aka tenant).
    pub owner: String,

    /// The permission grant used to authorize the message
    pub grant: Option<Grant>,
}

impl Context {
    /// Create a new context.
    #[must_use]
    pub fn new(owner: &str) -> Self {
        Self {
            owner: owner.to_string(),
            ..Self::default()
        }
    }
}
