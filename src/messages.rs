//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use crate::{Cursor, DateRange, Descriptor, Interface, Method};

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
