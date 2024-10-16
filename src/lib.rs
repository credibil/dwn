//! # Decentralized Web Node (DWN)

pub mod infosec;
pub mod messages;
pub mod protocols;
pub mod provider;
pub mod records;
pub mod service;
pub mod cid;

use serde::{Deserialize, Serialize};

use crate::provider::Provider;
use crate::service::Message;

/// Send a message.
pub async fn send_message(_: Message, _: impl Provider) -> anyhow::Result<()> {
    println!("Sending message");
    Ok(())
}

/// The message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// The associated DWN interface.
    pub interface: Interface,

    /// The interface method.
    pub method: Method,

    // The timestamp of the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_timestamp: Option<String>,
}

/// DWN interfaces.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Interface {
    /// Records interface.
    #[default]
    Records,

    /// Protocols interface.
    Protocols,

    /// Messages interface.
    Messages,
}

/// Interface methods.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

// /// Filter.
// #[derive(Clone, Debug, Deserialize, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub enum Filter {
//     /// Filter by a specific value.
//     Equal(Value),

//     OneOf(Vec<Value>)

//     /// Filter tags by range.
//     Range(SizeRange),
// }

// export type EqualFilter = string | number | boolean;
// export type OneOfFilter = EqualFilter[];
// export type RangeFilter = (GT | LT) & Partial<GT> & Partial<LT>;
// export type RangeValue = string | number;
