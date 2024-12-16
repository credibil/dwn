//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::provider::Provider;
use crate::{Descriptor, Result, schema, unauthorized};

/// Handle incoming messages.
///
/// # Errors
/// LATER: Add errors
pub async fn handle<T>(
    owner: &str, message: impl Message<Reply = T>, provider: &impl Provider,
) -> Result<Reply<T>> {
    message.validate(owner, provider).await?;
    message.handle(owner, provider).await
}

/// Methods common to all messages.
pub trait Message: Serialize + Clone + Debug + Send + Sync {
    /// The message's inner reply type.
    type Reply;

    /// Compute the CID of the message.
    ///
    /// # Errors
    /// LATER: Add errors
    fn cid(&self) -> Result<String>;

    /// Returns the component of the message descriptor common to all messages
    fn descriptor(&self) -> &Descriptor;

    /// Returns the messages's authorization, if set.
    fn authorization(&self) -> Option<&Authorization>;

    /// Handle the message.
    fn handle(
        self, owner: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Reply<Self::Reply>>> + Send;

    /// Validate the message. This is a generic validation common to all messages.
    /// Message-specific validation is done in the message handler.
    fn validate(
        &self, _owner: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant_gate.active(owner)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }

            schema::validate(self)?;

            // authenticate the requestor
            if let Some(authzn) = self.authorization() {
                if let Err(e) = authzn.authenticate(provider.clone()).await {
                    return Err(unauthorized!("failed to authenticate: {e}"));
                }
            }

            Ok(())
        }
    }
}

/// Reply used by all endpoints.
#[derive(Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Reply<ReplyBody> {
    /// Status message to accompany the reply.
    pub status: Status,

    /// Endpoint-specific reply.
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
