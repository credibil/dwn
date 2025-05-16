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

use std::fmt::Debug;

use tracing::instrument;

pub use crate::endpoint::{Body, Handler, Headers, IntoHttp, NoHeaders, Request, Response};
pub use crate::error::Error;
use crate::provider::Provider;

/// DWN handler `Result` type.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

/// Handle incoming DWN messages.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the incoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
#[instrument(level = "debug", skip(provider))]
pub async fn handle<B, H, P, U>(
    verifier: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    P: Provider,
    Request<B, H>: Handler<P, Response = U, Provider = P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    request.validate(verifier, provider).await?;
    Ok(request.handle(verifier, provider).await?.into())
}
