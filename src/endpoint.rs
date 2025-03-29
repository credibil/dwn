//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

use std::fmt::Debug;

use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::handlers::{
    messages_query, messages_read, messages_subscribe, protocols_configure, protocols_query,
    records_delete, records_query, records_read, records_subscribe, records_write,
};
use crate::interfaces::{Descriptor, messages, protocols, records};
use crate::provider::Provider;
use crate::{Error, Result, bad, schema, unauthorized};

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
pub async fn handle(
    owner: &str, message: impl Into<Message>, provider: &impl Provider,
) -> Result<Reply> {
    let message = message.into();
    message.validate(owner, provider).await?;
    message.handle(owner, provider).await
}

/// `Message` unifies all DWN messages into a single type for use with the
/// [`handle`] method.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Message {
    MessagesQuery(messages::Query),
    MessagesRead(messages::Read),
    MessagesSubscribe(messages::Subscribe),
    ProtocolsConfigure(protocols::Configure),
    ProtocolsQuery(protocols::Query),
    RecordsDelete(records::Delete),
    RecordsQuery(records::Query),
    RecordsRead(records::Read),
    RecordsSubscribe(records::Subscribe),
    RecordsWrite(records::Write),
}

impl From<messages::Query> for Message {
    fn from(message: messages::Query) -> Self {
        Self::MessagesQuery(message)
    }
}
impl From<messages::Read> for Message {
    fn from(message: messages::Read) -> Self {
        Self::MessagesRead(message)
    }
}
impl From<messages::Subscribe> for Message {
    fn from(message: messages::Subscribe) -> Self {
        Self::MessagesSubscribe(message)
    }
}
impl From<protocols::Configure> for Message {
    fn from(message: protocols::Configure) -> Self {
        Self::ProtocolsConfigure(message)
    }
}
impl From<protocols::Query> for Message {
    fn from(message: protocols::Query) -> Self {
        Self::ProtocolsQuery(message)
    }
}
impl From<records::Delete> for Message {
    fn from(message: records::Delete) -> Self {
        Self::RecordsDelete(message)
    }
}
impl From<records::Query> for Message {
    fn from(message: records::Query) -> Self {
        Self::RecordsQuery(message)
    }
}
impl From<records::Read> for Message {
    fn from(message: records::Read) -> Self {
        Self::RecordsRead(message)
    }
}
impl From<records::Subscribe> for Message {
    fn from(message: records::Subscribe) -> Self {
        Self::RecordsSubscribe(message)
    }
}
impl From<records::Write> for Message {
    fn from(message: records::Write) -> Self {
        Self::RecordsWrite(message)
    }
}

impl Message {
    const fn authorization(&self) -> Option<&Authorization> {
        match self {
            Self::MessagesQuery(m) => Some(&m.authorization),
            Self::MessagesRead(m) => Some(&m.authorization),
            Self::MessagesSubscribe(m) => Some(&m.authorization),
            Self::ProtocolsConfigure(m) => Some(&m.authorization),
            Self::ProtocolsQuery(m) => m.authorization.as_ref(),
            Self::RecordsDelete(m) => Some(&m.authorization),
            Self::RecordsQuery(m) => m.authorization.as_ref(),
            Self::RecordsRead(m) => m.authorization.as_ref(),
            Self::RecordsSubscribe(m) => m.authorization.as_ref(),
            Self::RecordsWrite(m) => Some(&m.authorization),
        }
    }

    pub(crate) const fn descriptor(&self) -> &Descriptor {
        match self {
            Self::MessagesQuery(m) => &m.descriptor.base,
            Self::MessagesRead(m) => &m.descriptor.base,
            Self::MessagesSubscribe(m) => &m.descriptor.base,
            Self::ProtocolsConfigure(m) => &m.descriptor.base,
            Self::ProtocolsQuery(m) => &m.descriptor.base,
            Self::RecordsDelete(m) => &m.descriptor.base,
            Self::RecordsQuery(m) => &m.descriptor.base,
            Self::RecordsRead(m) => &m.descriptor.base,
            Self::RecordsSubscribe(m) => &m.descriptor.base,
            Self::RecordsWrite(m) => &m.descriptor.base,
        }
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply> {
        match self {
            Self::MessagesQuery(m) => messages_query::handle(owner, m, provider).await,
            Self::MessagesRead(m) => messages_read::handle(owner, m, provider).await,
            Self::MessagesSubscribe(message) => {
                messages_subscribe::handle(owner, message, provider).await
            }
            Self::ProtocolsConfigure(message) => {
                protocols_configure::handle(owner, message, provider).await
            }
            Self::ProtocolsQuery(m) => protocols_query::handle(owner, m, provider).await,
            Self::RecordsDelete(m) => records_delete::handle(owner, m, provider).await,
            Self::RecordsQuery(m) => records_query::handle(owner, m, provider).await,
            Self::RecordsRead(m) => records_read::handle(owner, m, provider).await,
            Self::RecordsSubscribe(m) => records_subscribe::handle(owner, m, provider).await,
            Self::RecordsWrite(m) => records_write::handle(owner, m, provider).await,
        }
    }

    async fn validate(&self, _owner: &str, provider: &impl Provider) -> Result<()> {
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

/// Top-level reply data structure common to all handler.
#[derive(Debug, Default)]
pub struct Reply {
    /// The status message to accompany the reply.
    pub status: Status,

    /// The endpoint-specific reply.
    pub body: Option<ReplyBody>,
}

use axum::body::Bytes;
use http::Response;

/// Trait for converting a `Result` into an HTTP response.
pub trait IntoHttp {
    /// The body type of the HTTP response.
    type Body: http_body::Body<Data = Bytes> + Send + 'static;

    /// Convert into an HTTP response.
    fn into_http(self) -> Response<Self::Body>;
}

impl IntoHttp for Result<Reply> {
    type Body = axum::body::Body;

    /// Create a new reply with the given status code and body.
    fn into_http(self) -> Response<Self::Body> {
        // TODO: handle errors and return StatusCode::SERVER_ERROR
        let result = match self {
            Ok(r) => {
                let body = serde_json::to_vec(&r.body).unwrap_or_default();
                Response::builder()
                    .status(r.status.code)
                    .header("Content-Type", "application/json")
                    .body(Self::Body::from(body))
            }
            Err(e) => {
                let body = serde_json::to_vec(&e).unwrap_or_default();
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Self::Body::from(body))
            }
        };
        result.unwrap_or_default()
    }
}

/// Reply status.
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// Status code.
    pub code: StatusCode,

    /// Status detail.
    pub detail: Option<String>,
}

/// `ReplyBody` unifies all DWN message replies into a single type for use with
/// the [`handle`] method.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(missing_docs, clippy::large_enum_variant)]
pub enum ReplyBody {
    MessagesQuery(messages::QueryReply),
    MessagesRead(messages::ReadReply),
    MessagesSubscribe(messages::SubscribeReply),
    ProtocolsConfigure(protocols::ConfigureReply),
    ProtocolsQuery(protocols::QueryReply),
    RecordsDelete(records::DeleteReply),
    RecordsQuery(records::QueryReply),
    RecordsRead(records::ReadReply),
    RecordsSubscribe(records::SubscribeReply),
    RecordsWrite(records::WriteReply),
}

impl TryFrom<ReplyBody> for messages::QueryReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::MessagesQuery(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for messages::ReadReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::MessagesRead(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for messages::SubscribeReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::MessagesSubscribe(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for protocols::ConfigureReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::ProtocolsConfigure(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for protocols::QueryReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::ProtocolsQuery(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for records::DeleteReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::RecordsDelete(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for records::QueryReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::RecordsQuery(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for records::ReadReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::RecordsRead(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for records::SubscribeReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::RecordsSubscribe(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
impl TryFrom<ReplyBody> for records::WriteReply {
    type Error = Error;

    fn try_from(reply: ReplyBody) -> Result<Self, Self::Error> {
        match reply {
            ReplyBody::RecordsWrite(reply) => Ok(reply),
            _ => Err(bad!("invalid conversion")),
        }
    }
}
