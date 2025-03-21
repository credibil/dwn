//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::interfaces::Descriptor;
use crate::provider::Provider;
use crate::{Result, schema, unauthorized};

/// Handle incoming messages.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the imcoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
pub async fn handle<T>(
    owner: &str, message: impl Message<Reply = T>, provider: &impl Provider,
) -> Result<Reply<T>> {
    message.validate(owner, provider).await?;
    message.handle(owner, provider).await
}

/// Methods common to all messages.
///
/// The primary role of this trait is to provide a common interface for
/// messages so they can be handled by [`handle`] method.
pub trait Message: Serialize + Clone + Debug + Send + Sync {
    /// The inner reply type specific to the implementing message.
    type Reply;

    /// Returns message descriptor properties common to all messages (i.e.,
    /// `interface`, `method`, and `message_timestamp`).
    fn descriptor(&self) -> &Descriptor;

    /// Returns the messages's authorization, when set.
    fn authorization(&self) -> Option<&Authorization>;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, owner: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Reply<Self::Reply>>> + Send;

    /// Perform initial validation of the message.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    fn validate(
        &self, _owner: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant_gate.active(owner)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }

            // validate the message schema during development
            #[cfg(debug_assertions)]
            schema::validate(self)?;

            // authenticate the requestor
            if let Some(authzn) = self.authorization() {
                if let Err(e) = authzn.verify(provider.clone()).await {
                    return Err(unauthorized!("failed to authenticate: {e}"));
                }
            }

            Ok(())
        }
    }
}

/// Top-level reply data structure common to all handler.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Reply<ReplyBody> {
    /// The status message to accompany the reply.
    pub status: Status,

    /// The endpoint-specific reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub body: Option<ReplyBody>,
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
