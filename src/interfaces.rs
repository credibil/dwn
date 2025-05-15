//! # Interfaces
//!
//! Interfaces are the main building blocks of a DWN. They define the
//! structure of the data that is exchanged between users and the DWN.
//!
//! The three primary interfaces are `Records`, `Protocols`, and `Messages`
//! with each having a subset of `Methods` that define the operations that can
//! be performed on the data.
//!
//! Interface methods are executed by sending JSON messages to the DWN which,
//! in turn, will respond with a JSON reply. This library provides the tools
//! to easily create and parse these messages.

pub mod messages;
pub mod protocols;
pub mod records;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::interfaces::protocols::Configure;
use crate::interfaces::records::{Delete, Write};
use crate::serde::rfc3339_micros;
use crate::{Interface, Method};

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
    #[serde(serialize_with = "rfc3339_micros")]
    pub message_timestamp: DateTime<Utc>,
}

/// `Document` is used to store and retrieve messages in a type-independent manner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Document {
    /// `RecordsWrite` message.
    Write(Write),

    /// `RecordsDelete` message.
    Delete(Delete),

    /// `ProtocolsConfigure` message.
    Configure(Configure),
}

impl Default for Document {
    fn default() -> Self {
        Self::Write(Write::default())
    }
}

impl Document {
    /// The message's CID.
    ///
    /// # Errors
    ///
    /// The underlying CID computation is not infallible and may fail if the
    /// message cannot be serialized to CBOR.
    pub fn cid(&self) -> anyhow::Result<String> {
        match self {
            Self::Write(write) => write.cid(),
            Self::Delete(delete) => delete.cid(),
            Self::Configure(configure) => configure.cid(),
        }
    }

    /// The message's CID.
    #[must_use]
    pub const fn descriptor(&self) -> &Descriptor {
        match self {
            Self::Write(write) => &write.descriptor.base,
            Self::Delete(delete) => &delete.descriptor.base,
            Self::Configure(configure) => &configure.descriptor.base,
        }
    }

    /// Returns the `RecordsWrite` message, when set.
    #[must_use]
    pub const fn as_write(&self) -> Option<&records::Write> {
        match &self {
            Self::Write(write) => Some(write),
            _ => None,
        }
    }

    /// Returns the `RecordsDelete` message, when set.
    #[must_use]
    pub const fn as_delete(&self) -> Option<&records::Delete> {
        match &self {
            Self::Delete(delete) => Some(delete),
            _ => None,
        }
    }

    /// Returns the `ProtocolsConfigure` message, when set.
    #[must_use]
    pub const fn as_configure(&self) -> Option<&Configure> {
        match &self {
            Self::Configure(configure) => Some(configure),
            _ => None,
        }
    }
}

impl datastore::Document for Document {
    fn cid(&self) -> anyhow::Result<String> {
        self.cid().map_err(Into::into)
    }
}
