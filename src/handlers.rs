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

pub use crate::endpoint::{Body, Handler, Headers, NoHeaders, Request, Response};
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

// /// Top-level reply data structure common to all handler.
// #[derive(Debug, Default)]
// pub struct Reply {
//     /// The status message to accompany the reply.
//     pub status: Status,

//     /// The endpoint-specific reply.
//     pub body: Option<ReplyBody>,
// }

// /// Trait for converting a `Result` into an HTTP response.
// pub trait IntoHttp {
//     /// The body type of the HTTP response.
//     type Body: http_body::Body<Data = Bytes> + Send + 'static;

//     /// Convert into an HTTP response.
//     fn into_http(self) -> Response<Self::Body>;
// }

// impl IntoHttp for Result<Reply> {
//     type Body = http_body_util::Full<Bytes>;

//     /// Create a new reply with the given status code and body.
//     fn into_http(self) -> Response<Self::Body> {
//         let result = match self {
//             Ok(r) => {
//                 let body = serde_json::to_vec(&r.body).unwrap_or_default();
//                 Response::builder()
//                     .status(r.status)
//                     .header(header::CONTENT_TYPE, "application/json")
//                     .body(Self::Body::from(body))
//             }
//             Err(e) => {
//                 let body = serde_json::to_vec(&e).unwrap_or_default();
//                 Response::builder()
//                     .status(StatusCode::INTERNAL_SERVER_ERROR)
//                     .header(header::CONTENT_TYPE, "application/json")
//                     .body(Self::Body::from(body))
//             }
//         };
//         result.unwrap_or_default()
//     }
// }

// /// Reply status.
// #[derive(Clone, Debug, Default)]
// pub struct Status {
//     /// Status code.
//     pub code: StatusCode,

//     /// Status detail.
//     pub detail: Option<String>,
// }

// /// `ReplyBody` unifies all DWN message replies into a single type for use with
// /// the [`handle`] method.
// #[derive(Debug, Deserialize, Serialize)]
// #[serde(untagged)]
// #[allow(missing_docs, clippy::large_enum_variant)]
// pub enum ReplyBody {
//     MessagesQuery(messages::QueryReply),
//     MessagesRead(messages::ReadReply),
//     MessagesSubscribe(messages::SubscribeReply),
//     ProtocolsConfigure(protocols::ConfigureReply),
//     ProtocolsQuery(protocols::QueryReply),
//     RecordsDelete(records::DeleteReply),
//     RecordsQuery(records::QueryReply),
//     RecordsRead(records::ReadReply),
//     RecordsSubscribe(records::SubscribeReply),
//     RecordsWrite(records::WriteReply),
// }

// impl TryFrom<ReplyBody> for messages::QueryReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::MessagesQuery(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for messages::ReadReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::MessagesRead(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for messages::SubscribeReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::MessagesSubscribe(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for protocols::ConfigureReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::ProtocolsConfigure(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for protocols::QueryReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::ProtocolsQuery(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for records::DeleteReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::RecordsDelete(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for records::QueryReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::RecordsQuery(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for records::ReadReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::RecordsRead(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for records::SubscribeReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::RecordsSubscribe(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
// impl TryFrom<ReplyBody> for records::WriteReply {
//     type Error = Error;

//     fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
//         match reply {
//             ReplyBody::RecordsWrite(reply) => Ok(reply),
//             _ => Err(bad!("invalid conversion")),
//         }
//     }
// }
