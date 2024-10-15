//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use crate::service::Authorization;
use crate::{Cursor, DateRange, Descriptor, Interface, Method};

/// Messages Query payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Messages Read payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Read {
    /// The Read descriptor.
    pub descriptor: ReadDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Messages Subscribe payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<Filter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Message CID.
    pub message_cid: String,
}

/// Suscribe descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Message CID.
    pub filters: Vec<Filter>,
}

/// Messages filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
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

/// Messages sort.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    /// Sort by `date_created`.
    pub date_created: Option<Direction>,

    /// Sort by `date_published`.
    pub date_published: Option<Direction>,

    /// Sort by `message_timestamp`.
    pub message_timestamp: Option<Direction>,
}

/// Sort direction.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// Sort ascending.
    #[default]
    Ascending = 1,

    /// Sort descending.
    Descending = -1,
}
