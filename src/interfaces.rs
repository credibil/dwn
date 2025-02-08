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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::interfaces::protocols::Configure;
use crate::interfaces::records::{Delete, Write};
use crate::serde::{rfc3339_micros, rfc3339_micros_opt};
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

/// `MessageType` wraps the message payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum MessageType {
    /// `RecordsWrite` message.
    Write(Write),

    /// `RecordsDelete` message.
    Delete(Delete),

    /// `ProtocolsConfigure` message.
    Configure(Configure),
}

impl Default for MessageType {
    fn default() -> Self {
        Self::Write(Write::default())
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
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub lower: Option<DateTime<Utc>>,

    /// The filter's upper bound.
    #[serde(rename = "to")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
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

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Cursor created form the previous page of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

impl Pagination {
    /// Create a new `Pagination` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limit: None,
            cursor: None,
            // offinner: None,
        }
    }

    /// Set the limit.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the cursor.
    #[must_use]
    pub fn cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

/// Pagination cursor containing data from the last entry returned in the
/// previous page of results.
///
/// Message CID ensures result cursor compatibility irrespective of DWN
/// implementation. Meaning querying with the same cursor yields identical
/// results regardless of DWN queried.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    /// Message CID from the last entry in the previous page of results.
    pub message_cid: String,

    /// The value (from sort field) of the last entry in the previous page of
    /// results.
    pub value: String,
}
