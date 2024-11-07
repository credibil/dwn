//! # Decentralized Web Node (web node)

pub mod auth;
pub mod cid;
pub mod messages;
pub mod permissions;
pub mod protocols;
pub mod provider;
pub mod query;
pub mod records;
mod schema;
pub mod service;
mod store;
mod utils;

use chrono::{DateTime, Utc};
use derive_more::Display;
use serde::{Deserialize, Serialize};

pub use crate::service::{handle_message, Message};

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: u64 = 30000;

/// The message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct Descriptor {
    /// The associated web node interface.
    pub interface: Interface,

    /// The interface method.
    pub method: Method,

    /// The timestamp of the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<DateTime<Utc>>,
}

/// web node interfaces.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
// #[serde(rename_all = "camelCase")]
pub enum Interface {
    /// Records interface.
    #[default]
    Records,

    /// Protocols interface.
    Protocols,

    /// Messages interface.
    Messages,
}

// impl Display for Interface {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", format!("{self:?}").to_lowercase())
//     }
// }

/// Interface methods.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
pub enum Method {
    /// Read method.
    #[default]
    Read,

    /// Write method.
    Write,

    /// Query method.
    Query,

    /// Subscribe method.
    Configure,

    /// Subscribe method.
    Subscribe,

    /// Delete method.
    Delete,
}

// impl Display for Method {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", format!("{self:?}").to_lowercase())
//     }
// }

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Protocol {
    /// IPFS protocol.
    #[default]
    Http,
}

/// `Quota` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Quota<T> {
    /// Single object
    One(T),

    /// Set of objects
    Many(Vec<T>),
}

impl<T: Default> Default for Quota<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

/// Date range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DateRange {
    /// Match messages with `message_timestamp` on or after.
    pub from: String,

    /// Match messages with `message_timestamp` on or before.
    pub to: String,
}

/// Reply status.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Status code.
    pub code: u16,

    /// Status detail.
    pub detail: Option<String>,
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// CID of message to start from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,

    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    /// CID of message to start from.
    pub message_cid: String,

    /// The number of messages to return.
    pub value: u64,
}
