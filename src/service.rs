//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::any::Any;
use std::fmt::Debug;
use std::future::Future;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::Authorization;
use crate::permissions::Grant;
use crate::provider::{MessageStore, Provider};
use crate::{permissions, schema, unexpected, Descriptor, Result, Status};

/// Methods common to all messages.
pub trait Message: Handler + Serialize + DeserializeOwned + Clone + Debug + Send + Sync {
    /// Compute the CID of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    fn cid(&self) -> Result<String>;

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

// pub enum Options {
//     /// The message is a write message.
//     Write(Write),

//     /// The message is a read message.
//     Read(Read),
// }

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
    //             detail: Some("{tenant} is not active),
    //         },
    //     }));
    // }
    let mut ctx = Context {
        owner: owner.to_string(),
        ..Context::default()
    };

    schema::validate(&message)?;
    if let Some(authzn) = message.authorization() {
        authzn.authenticate(&provider).await?;
    };
    authorize(&message, &mut ctx, &provider).await?;
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
        return Err(unexpected!("`permission_grant_id` not found in signature payload",));
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
