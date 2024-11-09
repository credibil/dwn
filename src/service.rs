//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::fmt::Debug;

use async_trait::async_trait;
// use std::future::Future;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::Authorization;
use crate::permissions::Grant;
use crate::provider::Provider;
use crate::{permissions, schema, unexpected, Descriptor, Result};

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
