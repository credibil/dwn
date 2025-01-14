#![feature(let_chains)]
// #![feature(type_changing_struct_update)]

//! # Decentralized Web Node (web node)

pub mod authorization;
pub mod data;
pub mod endpoint;
mod error;
pub mod event;
pub mod hd_key;
pub mod messages;
pub mod permissions;
pub mod protocols;
pub mod provider;
pub mod records;
pub mod schema;
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
pub struct Range<T: PartialOrd> {
    /// The range's minimum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<T>,

    /// The range's maximum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<T>,
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RangeFilter<T: PartialOrd> {
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
pub enum Lower<T: PartialOrd> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "gt")]
    GreaterThan(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "gte")]
    GreaterThanOrEqual(T),
}

impl<T: PartialOrd + Default> Default for Lower<T> {
    fn default() -> Self {
        Self::GreaterThan(T::default())
    }
}

/// Range upper bound comparision options.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Upper<T: PartialOrd> {
    /// Lower bound compare is greater than the specified value.
    #[serde(rename = "lt")]
    LessThan(T),

    /// Lower bound compare is greater than or equal to.
    #[serde(rename = "lte")]
    LessThanOrEqual(T),
}

impl<T: PartialOrd + Default> Default for Upper<T> {
    fn default() -> Self {
        Self::LessThan(T::default())
    }
}

impl<T: PartialOrd> RangeFilter<T> {
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
        self.lower = Some(Lower::GreaterThan(gt));
        self
    }

    /// Specify a 'greater-than-or-equal' lower bound for the filter.
    #[must_use]
    pub fn ge(mut self, ge: T) -> Self {
        self.lower = Some(Lower::GreaterThanOrEqual(ge));
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub fn lt(mut self, lt: T) -> Self {
        self.upper = Some(Upper::LessThan(lt));
        self
    }

    /// Specify a 'less-than-or-equal' upper bound for the filter.
    #[must_use]
    pub fn le(mut self, le: T) -> Self {
        self.upper = Some(Upper::LessThanOrEqual(le));
        self
    }

    /// Check if the range contains the value.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialOrd,
    {
        let lower_ok = match &self.lower {
            Some(Lower::GreaterThan(lower)) => value > lower,
            Some(Lower::GreaterThanOrEqual(lower)) => value >= lower,
            None => true,
        };
        if !lower_ok {
            return false;
        }

        match &self.upper {
            Some(Upper::LessThan(upper)) => value < upper,
            Some(Upper::LessThanOrEqual(upper)) => value <= upper,
            None => true,
        }
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
