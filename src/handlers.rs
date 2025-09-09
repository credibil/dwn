//! # Handlers
//!
//! This module contains the DWN message handlers — one for each
//! interface/method message.

mod messages_query;
mod messages_read;
mod messages_subscribe;
mod protocols_configure;
mod protocols_query;
mod records_delete;
mod records_query;
mod records_read;
mod records_subscribe;
mod records_write;
mod verify_grant;
mod verify_protocol;

use std::future::Future;

use credibil_api::Body;
use credibil_binding::Resolver;
use serde::Serialize;

use crate::authorization::Authorization;
pub use crate::error::Error;
use crate::error::unauthorized;
use crate::interfaces::Descriptor;
use crate::schema;

/// A type alias for the result type used throughout the handlers module.
pub type Result<T> = anyhow::Result<T, Error>;

/// The `BodyExt` trait is used to restrict the types able to implement
/// request body. It is implemented by all `xxxRequest` types.
pub trait BodyExt: Body + Serialize {
    /// The request's 'core' descriptor.
    fn descriptor(&self) -> &Descriptor;

    /// the Request's authorization, if any.
    fn authorization(&self) -> Option<&Authorization>;

    /// Perform initial validation of the request.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    ///
    /// # Errors
    ///
    /// Will fail if the request is invalid or if authentication fails.
    fn validate(&self, resolver: &impl Resolver) -> impl Future<Output = Result<()>> + Send {
        async {
            // if !tenant.active(owner)? {
            //     return Err(Error::Unauthorized("tenant not active"));
            // }

            #[cfg(debug_assertions)]
            schema::validate(self)?;

            // authenticate the requestor
            if let Some(authzn) = self.authorization()
                && let Err(e) = authzn.verify(resolver).await
            {
                return Err(unauthorized!("failed to authenticate: {e}"));
            }

            Ok(())
        }
    }
}
