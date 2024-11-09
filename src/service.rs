//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::any::Any;
use std::fmt::Debug;

// use std::future::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::Authorization;
use crate::permissions::Grant;
use crate::provider::Provider;
use crate::{permissions, schema, unexpected, Descriptor, Result, Status};

/// Methods common to all messages.
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

    /// Authorize the message.
    async fn validate(&self, ctx: &mut Context, provider: &impl Provider) -> Result<()> {
        schema::validate(self)?;

        // message has no authorization
        let Some(authzn) = self.authorization() else {
            return Ok(());
        };

        // authenticate the message
        authzn.authenticate(provider).await?;

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

/// Reply to a web node message.
pub trait Reply: Serialize + Clone + Debug {
    /// Status message to accompany the reply.
    fn status(&self) -> Status;

    /// `Any` supports downcasting the trait object to it's underlying type.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let reply = handle_message(owner, message, provider).await?;
    /// let reply = reply.as_any().downcast_ref::<RecordsReadReply>().unwrap();
    /// ```
    fn as_any(&self) -> &dyn Any;
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
