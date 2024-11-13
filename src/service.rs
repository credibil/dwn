//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::fmt::Debug;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::auth::Authorization;
use crate::permissions::{self, Grant};
use crate::provider::Provider;
use crate::{protocols, records, schema, unexpected, Descriptor, Error, Result};

/// Wraps each message with a unifying type used in operations common to all
/// messages. For example, storing and retrieving from the `MessageStore`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageRecord {
    /// The message type.
    #[serde(flatten)]
    pub inner: Messages,

    /// Flattened message indexes.
    #[serde(flatten)]
    pub indexes: Map<String, Value>,
}

impl MessageRecord {
    /// The message's CID.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn cid(&self) -> Result<String> {
        match self.inner {
            Messages::RecordsWrite(ref write) => write.cid(),
            Messages::ProtocolsConfigure(ref configure) => configure.cid(),
        }
    }

    /// The message's CID.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor {
        match self.inner {
            Messages::RecordsWrite(ref write) => write.descriptor(),
            Messages::ProtocolsConfigure(ref configure) => configure.descriptor(),
        }
    }
}

impl MessageRecord {
    /// Return the `RecordsWrite` message, if set.
    #[must_use]
    pub const fn as_write(&self) -> Option<&records::Write> {
        match &self.inner {
            Messages::RecordsWrite(write) => Some(write),
            Messages::ProtocolsConfigure(_) => None,
        }
    }

    /// Return the `ProtocolsConfigure` message, if set.
    #[must_use]
    pub const fn as_configure(&self) -> Option<&protocols::Configure> {
        match &self.inner {
            Messages::ProtocolsConfigure(configure) => Some(configure),
            Messages::RecordsWrite(_) => None,
        }
    }
}

/// Records read message payload
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Messages {
    /// Records write message.
    RecordsWrite(records::Write),

    /// Protocols configure message.
    ProtocolsConfigure(protocols::Configure),
}

/// Methods common to all messages.
#[async_trait]
pub trait Message: Serialize + DeserializeOwned + Clone + Debug + Send + Sync {
    /// Compute the CID of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    fn cid(&self) -> Result<String>;

    /// Returns the component of the message descriptor common to all messages
    fn descriptor(&self) -> &Descriptor;

    /// Returns the messages's authorization, if set.
    fn authorization(&self) -> Option<&Authorization>;

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
