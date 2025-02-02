#![feature(let_chains)]

//! # Decentralized Web Node (DWN)
//!
//! A [Decentralized Web Node (DWN)] is a data storage and message relay
//! mechanism entities can use to locate public or private permissioned data
//! related to a given Decentralized Identifier (DID). Decentralized Web Nodes
//! are designed to be deployed in mesh-like datastore construct that enables
//! an entity to operate multiple nodes that replicate state across all nodes.
//!
//! A DWN allows the owning entity to secure, manage, and transact data with
//! others without reliance on location or provider-specific infrastructure,
//! interfaces, or routing mechanisms.
//!
//! [Decentralized Web Node (DWN)]: https://identity.foundation/working-groups/didcomm-messaging/spec/#decentralized-web-node-dwn

pub mod authorization;
pub mod endpoint;
mod error;
pub mod event;
pub mod hd_key;
pub mod interfaces;
pub(crate) mod messages;
pub mod permissions;
pub(crate) mod protocols;
pub mod provider;
pub(crate) mod records;
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
pub use crate::utils::cid;

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
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
pub enum Method {
    /// Read method.
    #[default]
    Read,
    /// Write method.
    Write,
    /// Query method.
    Query,
    /// Configure method.
    Configure,
    /// Subscribe method.
    Subscribe,
    /// Delete method.
    Delete,
}

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Protocol {
    /// HTTP protocol.
    #[default]
    Http,
}

/// `OneOrMany` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single object.
    One(T),
    /// A set of objects.
    Many(Vec<T>),
}

impl<T: Default> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T: Clone> OneOrMany<T> {
    /// Convert the quota to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Many(value)
    }
}

/// Range to use in filters.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Range<T: PartialEq> {
    /// The filter's lower bound.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lower: Option<Lower<T>>,

    /// The filter's upper bound.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper: Option<Upper<T>>,
}

/// Range lower bound comparision options.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Lower<T: PartialEq> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "gt")]
    Exclusive(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "gte")]
    Inclusive(T),
}

impl<T: PartialEq + Default> Default for Lower<T> {
    fn default() -> Self {
        Self::Exclusive(T::default())
    }
}

/// Range upper bound comparision options.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Upper<T: PartialEq> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "lt")]
    Exclusive(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "lte")]
    Inclusive(T),
}

impl<T: PartialEq + Default> Default for Upper<T> {
    fn default() -> Self {
        Self::Exclusive(T::default())
    }
}

impl<T: PartialEq> Range<T> {
    /// Create a new range filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    /// Specify a 'greater-than' lower bound for the filter.
    #[must_use]
    pub fn gt(mut self, gt: T) -> Self {
        self.lower = Some(Lower::Exclusive(gt));
        self
    }

    /// Specify a 'greater-than-or-equal' lower bound for the filter.
    #[must_use]
    pub fn ge(mut self, ge: T) -> Self {
        self.lower = Some(Lower::Inclusive(ge));
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub fn lt(mut self, lt: T) -> Self {
        self.upper = Some(Upper::Exclusive(lt));
        self
    }

    /// Specify a 'less-than-or-equal' upper bound for the filter.
    #[must_use]
    pub fn le(mut self, le: T) -> Self {
        self.upper = Some(Upper::Inclusive(le));
        self
    }

    /// Check if the range contains the value.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialOrd,
    {
        let lower_ok = match &self.lower {
            Some(Lower::Exclusive(lower)) => value > lower,
            Some(Lower::Inclusive(lower)) => value >= lower,
            None => true,
        };
        if !lower_ok {
            return false;
        }

        match &self.upper {
            Some(Upper::Exclusive(upper)) => value < upper,
            Some(Upper::Inclusive(upper)) => value <= upper,
            None => true,
        }
    }
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DateRange {
    /// The filter's lower bound.
    #[serde(rename = "from")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serde::rfc3339_micros_opt")]
    pub lower: Option<DateTime<Utc>>,

    /// The filter's upper bound.
    #[serde(rename = "to")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serde::rfc3339_micros_opt")]
    pub upper: Option<DateTime<Utc>>,
}

impl DateRange {
    /// Create a new range filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    /// Specify a 'greater-than' lower bound for the filter.
    #[must_use]
    pub const fn gt(mut self, gt: DateTime<Utc>) -> Self {
        self.lower = Some(gt);
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub const fn lt(mut self, lt: DateTime<Utc>) -> Self {
        self.upper = Some(lt);
        self
    }

    /// Check if the range contains the value.
    #[must_use]
    pub fn contains(&self, value: &DateTime<Utc>) -> bool {
        if let Some(lower) = &self.lower {
            if value < lower {
                return false;
            }
        }
        if let Some(upper) = &self.upper {
            if value >= upper {
                return false;
            }
        }

        true
    }
}

// Custom serialization functions.
mod serde {
    use chrono::SecondsFormat::Micros;
    use chrono::{DateTime, Utc};
    use serde::Serializer;

    /// Force serializing to an RFC 3339 string with microsecond precision.
    pub fn rfc3339_micros<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339_opts(Micros, true);
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
