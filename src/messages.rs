//! # Messages

pub mod query;
pub mod read;
pub mod subscribe;

use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryBuilder, QueryReply};
pub use self::read::{Read, ReadBuilder, ReadReply};
pub use self::subscribe::{Subscribe, SubscribeBuilder, SubscribeReply};
use crate::{Interface, Method, Range};

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
    pub message_timestamp: Option<Range<String>>,
}
