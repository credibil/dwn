#![feature(let_chains)]

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
pub mod store;
mod tasks;
mod utils;

use chrono::{DateTime, Utc};
use derive_more::Display;
use serde::{Deserialize, Serialize};

pub use crate::endpoint::Message;
pub use crate::error::Error;
pub use crate::provider::Provider;

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
    pub message_timestamp: DateTime<Utc>,
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

impl<T: Clone> Quota<T> {
    /// Convert the quota to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Range<T> {
    /// The minimum value.
    pub start: Option<T>,

    /// The maximum value.
    pub end: Option<T>,
}

impl<T> Range<T> {
    /// Create a new range filter.
    pub const fn new(start: Option<T>, end: Option<T>) -> Self {
        Self { start, end }
    }

    /// Check if the range contains the value.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialOrd,
    {
        if let Some(start) = &self.start
            && value < start
        {
            return false;
        }
        if let Some(end) = &self.end
            && value > end
        {
            return false;
        }

        true
    }
}

// #[cfg(test)]
// mod tests {
//     use std::ops::Range;

//     use super::{DateTime, Utc};

//     #[test]
//     fn test_range() {
//         let min_date = DateTime::<Utc>::MIN_UTC;
//         let max_date = Utc::now();

//         let range = Range {
//             start: Some(min_date),
//             end: Some(max_date),
//         };

//         let betw = Utc::now() - chrono::Duration::days(1);
//         println!("{:?}", range.contains(&Some(betw)));
//     }
// }
