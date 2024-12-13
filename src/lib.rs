#![feature(let_chains)]
// #![feature(type_changing_struct_update)]

//! # Decentralized Web Node (web node)

pub mod authorization;
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
pub mod store;
mod tasks;
mod utils;

use ::serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use derive_more::Display;

pub use crate::endpoint::Message;
pub use crate::error::Error;
pub use crate::provider::Provider;
use crate::serde::rfc3339_micros;

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
    #[serde(serialize_with = "rfc3339_micros")]
    pub message_timestamp: DateTime<Utc>,
}

/// Web node interfaces.
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

impl<T: Clone> Quota<T> {
    /// Convert the quota to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

impl<T> From<T> for Quota<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for Quota<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Many(value)
    }
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Range<T> {
    /// The minimum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<T>,

    /// The maximum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<T>,
}

impl<T> Range<T> {
    /// Create a new range filter.
    pub const fn new(min: Option<T>, max: Option<T>) -> Self {
        Self { min, max }
    }

    /// Check if the range contains the value.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialOrd,
    {
        if let Some(min) = &self.min
            && value < min
        {
            return false;
        }
        if let Some(max) = &self.max
            && value > max
        {
            return false;
        }

        true
    }
}

// Custom serialization functions.
mod serde {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::Serializer;

    /// Force serializing to an RFC 3339 string with microsecond precision.
    pub fn rfc3339_micros<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339_opts(SecondsFormat::Micros, true);
        serializer.serialize_str(&s)
    }

    /// Force serializing to an RFC 3339 string with microsecond precision.
    #[allow(clippy::ref_option)]
    pub fn rfc3339_micros_opt<S>(
        date: &Option<DateTime<Utc>>, serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Some(date) = date else {
            return serializer.serialize_none();
        };
        rfc3339_micros(date, serializer)
    }
}
