//! # Messages Interface
//!
//! The `Messages` interface provides methods to query, read, and subscribe to
//! any DWN message regardless of the interface or method.

mod query;
mod read;
mod subscribe;

use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryDescriptor, QueryReply};
pub use self::read::{Read, ReadDescriptor, ReadReply};
pub use self::subscribe::{Subscribe, SubscribeDescriptor, SubscribeReply};
use crate::{DateRange, Interface, Method};

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
