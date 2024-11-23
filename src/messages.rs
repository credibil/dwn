//! # Messages

pub mod query;
pub mod read;
pub mod subscribe;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryBuilder, QueryReply};
pub use self::read::{Read, ReadBuilder, ReadReply};
pub use self::subscribe::{Subscribe, SubscribeBuilder, SubscribeReply};
use crate::store::QuerySerializer;
use crate::{Interface, Method, Range};

/// `Messages` filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesFilter {
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
    pub message_timestamp: Option<Range<String>>,
}

impl QuerySerializer for MessagesFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = String::from("1=1\n");

        if let Some(interface) = &self.interface {
            sql.push_str(&format!("AND descriptor.interface = '{interface}'\n"));
        }
        if let Some(method) = &self.method {
            sql.push_str(&format!("AND descriptor.method = '{method}'\n"));
        }
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND descriptor.protocol = '{protocol}'\n"));
        }
        if let Some(timestamp) = &self.message_timestamp {
            let min = &DateTime::<Utc>::MIN_UTC.to_rfc3339();
            let max = &Utc::now().to_rfc3339();

            let from = timestamp.min.as_ref().unwrap_or(min);
            let to = timestamp.max.as_ref().unwrap_or(max);
            sql.push_str(&format!("AND descriptor.messageTimestamp BETWEEN '{from}' AND '{to}'\n"));
        }

        sql
    }
}
