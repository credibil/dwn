//! # Messages Query
//!
//! The messages query endpoint handles `MessagesQuery` messages — requests
//! to query the [`crate::provider::EventLog`] for matching persisted messages
//! (of any type).

use std::io;

use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::event::Subscriber;
use crate::interfaces::{Descriptor, Document};
use crate::store::{Cursor, DateRange};
use crate::{Interface, Method};

/// The [`Query`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The `Query` descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// The [`Query`] message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying for messages.
    pub filters: Vec<MessagesFilter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// [`QueryReply`] is returned by the handler in the [`crate::endpoint::Reply`]
/// `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryReply {
    /// Entries matching the message's query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// The [`Read`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Read {
    /// The `Read` descriptor.
    pub descriptor: ReadDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// The [`Read`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The CID of the message to read.
    pub message_cid: String,
}

/// [`ReadReply`] is returned by the handler in the [`crate::endpoint::Reply`]
/// `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReadReply {
    /// The `Read` descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<ReadReplyEntry>,
}

/// `Read` reply entry
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ReadReplyEntry {
    /// The CID of the message.
    pub message_cid: String,

    /// The message.
    pub message: Document,

    /// The data associated with the message.
    #[serde(skip)]
    pub data: Option<io::Cursor<Vec<u8>>>,
}

/// The [`Subscribe`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// The [`Subscribe`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when subscribing to messages.
    pub filters: Vec<MessagesFilter>,
}

/// [`SubscribeReply`] is returned by the handler in the
/// [`crate::endpoint::Reply`] `body` field.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    #[serde(skip)]
    pub subscription: Subscriber,
}

/// The `Messages` can be used to filter messages by interface, method,
/// protocol, and timestamp.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesFilter {
    /// The message interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<Interface>,

    /// The message method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Method>,

    /// The message protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Filter messages timestamped within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<DateRange>,
}

/// Provide  builder-like behaviour to create a [`MessagesFilter`].
impl MessagesFilter {
    /// Returns a new [`MessagesFilter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify the interface to filter mesages on.
    #[must_use]
    pub const fn interface(mut self, interface: Interface) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Specify the method to filter mesages on.
    #[must_use]
    pub const fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    /// Specify a protocol to filter messages by.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Filter by message timestamp.
    #[must_use]
    pub const fn message_timestamp(mut self, message_timestamp: DateRange) -> Self {
        self.message_timestamp = Some(message_timestamp);
        self
    }
}
