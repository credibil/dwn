//! # Decentralized Web Node (web node)

mod auth;
pub mod data;
pub mod endpoint;
mod error;
pub mod event;
pub mod messages;
pub mod permissions;
pub mod protocols;
pub mod provider;
pub mod records;
mod schema;
mod store;
mod utils;

use chrono::{DateTime, Utc};
use derive_more::Display;
use serde::{Deserialize, Serialize};

pub use crate::endpoint::Message;
pub use crate::error::Error;
pub use crate::provider::Provider;

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 5; //30000;

/// Result type for `DWN` handlers.
pub type Result<T, E = Error> = std::result::Result<T, E>;

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
#[allow(missing_docs)]
pub enum Interface {
    #[default]
    Records,
    Protocols,
    Messages,
}

/// Interface methods.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Method {
    #[default]
    Read,
    Write,
    Query,
    Configure,
    Subscribe,
    Delete,
}

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum Protocol {
    #[default]
    Http,
}

/// `Quota` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Quota<T> {
    One(T),
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
