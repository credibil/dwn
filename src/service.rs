//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::fmt::Debug;
use std::future::Future;

use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::auth::Authorization;
use crate::permissions::Grant;
use crate::provider::{MessageStore, Provider};
use crate::{permissions, schema, Descriptor, Status};

/// Methods common to all messages.
pub trait Message: Handler + DeserializeOwned + Serialize + Clone + Debug + Send + Sync {
    /// Compute the CID of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    fn cid(&self) -> anyhow::Result<String>;

    /// Returns the component of the message descriptor common to all messages
    fn descriptor(&self) -> &Descriptor;

    /// Returns the messages's authorization, if set.
    fn authorization(&self) -> Option<&Authorization>;
}

/// Handler is implemented by messages processed by web nodes.
pub trait Handler {
    /// Handle the message.
    fn handle(
        self, ctx: Context, provider: impl Provider,
    ) -> impl Future<Output = Result<impl Reply>> + Send;
}

/// Reply to a web node message.
pub trait Reply: Serialize + Debug {
    /// Status message to accompany the reply.
    fn status(&self) -> Status;
}

/// Process web node messages.
///
/// # Errors
/// TODO: Add errors
pub async fn handle_message(
    owner: &str, message: impl Message, provider: impl Provider,
) -> Result<impl Reply> {
    // if !tenant_gate.active(owner)? {
    //     return Ok(Reply::GenericReply(GenericReply {
    //         status: Status {
    //             code: 401,
    //             detail: Some("{tenant} is not active".to_string()),
    //         },
    //     }));
    // }

    // validate message against schema
    schema::validate(&message)?;

    let mut ctx = Context {
        owner: owner.to_string(),
        ..Context::default()
    };

    // authenticate author
    if let Some(authzn) = message.authorization() {
        authzn.authenticate(&provider).await?;
    };

    // base authorization
    authorize(&message, &mut ctx, &provider).await?;

    // forward to message-specific handler
    message.handle(ctx, provider).await
}

/// Authorize the message.
///
/// # Errors
/// TODO: Add errors
async fn authorize(
    message: &impl Message, ctx: &mut Context, store: &impl MessageStore,
) -> Result<()> {
    // message has no authorization
    let Some(authzn) = message.authorization() else {
        return Ok(());
    };
    ctx.author = authzn.author()?;

    // no checks needed when message author is web node owner
    if ctx.author == ctx.owner {
        return Ok(());
    }

    let payload = authzn.jws_payload()?;
    let Some(grant_id) = &payload.permission_grant_id else {
        return Err(anyhow!("`permission_grant_id` not found in signature payload"));
    };

    let grant = permissions::fetch_grant(&ctx.owner, grant_id, store).await?;
    grant.verify(&ctx.author, &authzn.signer()?, message.descriptor(), store).await?;

    // save for later use
    ctx.grant = Some(grant);

    Ok(())
}

/// Message context for attaching information used during processing.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The web node owner (aka tenant).
    pub owner: String,

    /// The author of the message.
    pub author: String,

    /// The permission grant used to authorize the message
    pub grant: Option<Grant>,
}

/// Reply to a web node message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ErrorReply {
    /// Status message to accompany the reply.
    pub status: Status,
}

impl Reply for ErrorReply {
    fn status(&self) -> Status {
        self.status.clone()
    }
}
