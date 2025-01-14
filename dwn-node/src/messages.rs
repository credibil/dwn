//! # Messages

mod query;
mod read;
mod subscribe;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryDescriptor, QueryReply};
pub use self::read::{Read, ReadDescriptor, ReadReply};
pub use self::subscribe::{Subscribe, SubscribeDescriptor, SubscribeReply};
use crate::{Interface, Method, RangeFilter};

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
