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

use crate::api::{Body, Error, Handler, Headers, Reply, Request, Result};
use crate::provider::Provider;

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
    owner: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Reply<U>>
where
    B: Body,
    H: Headers,
    P: Provider,
    Request<B, H>: Handler<U, P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    request.validate(owner, provider).await?;
    Ok(request.handle(owner, provider).await?.into())
}
