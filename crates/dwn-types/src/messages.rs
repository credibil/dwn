//! # Messages

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::event::Subscriber;
use crate::records::DataStream;
use crate::store::{Cursor, EntryType};
use crate::{Descriptor, Interface, Method, RangeFilter};

/// `Query` payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The `Query` descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// `Query` reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct QueryReply {
    /// Entries matching the message's query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// `Query` descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<MessagesFilter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// `Read` payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Read {
    /// The `Read` descriptor.
    pub descriptor: ReadDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// `Read` reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ReadReply {
    /// The `Read` descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<ReadReplyEntry>,
}

/// `Read` reply entry
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ReadReplyEntry {
    /// The CID of the message.
    pub message_cid: String,

    /// The message.
    pub message: EntryType,

    /// The data associated with the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DataStream>,
}

/// Read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The CID of the message to read.
    pub message_cid: String,
}

/// Subscribe reply
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    #[serde(skip)]
    pub subscription: Subscriber,
}

/// Subscribe descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when subscribing to messages.
    pub filters: Vec<MessagesFilter>,
}

/// `Messages` filter.
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
    pub message_timestamp: Option<RangeFilter<DateTime<Utc>>>,
}

/// Implement  builder-like behaviour.
impl MessagesFilter {
    /// Returns a new [`RecordsFilter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add interface to the filter.
    #[must_use]
    pub const fn interface(mut self, interface: Interface) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Add method to the filter.
    #[must_use]
    pub const fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    /// Add protocol to the filter.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Add message timestamp to the filter.
    #[must_use]
    pub const fn message_timestamp(
        mut self, message_timestamp: RangeFilter<DateTime<Utc>>,
    ) -> Self {
        self.message_timestamp = Some(message_timestamp);
        self
    }
}
