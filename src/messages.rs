//! # Messages
//!
//! Decentralized Web Node messaging framework.

pub mod query;
pub mod read;

use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryBuilder, QueryReply};
pub use self::read::{Read, ReadBuilder, ReadReply};
use crate::auth::Authorization;
use crate::{DateRange, Descriptor, Interface, Method};

/// Message event.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Event {
    /// Event descriptor.
    #[serde(flatten)]
    pub base: Descriptor,

    /// Message protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// The message's CID.
    pub message_cid: String,
}

/// Messages Subscribe payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
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

impl Filter {
    fn to_sql(&self) -> String {
        let mut sql = String::from("1=1\n");

        if let Some(interface) = &self.interface {
            sql.push_str(&format!("AND descriptor.interface = '{interface}'\n"));
        }
        if let Some(method) = &self.method {
            sql.push_str(&format!("AND descriptor.method = '{method}'\n"));
        }
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND protocol = '{protocol}'\n"));
        }
        if let Some(timestamp) = &self.message_timestamp {
            sql.push_str(&format!(
                "AND descriptor.messageTimestamp BETWEEN {from} AND {to}'\n",
                from = timestamp.from,
                to = timestamp.to
            ));
        }

        sql
    }
}

// /// Messages sort.
// #[derive(Clone, Debug, Default, Deserialize, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub struct Sort {
//     /// Sort by `date_created`.
//     pub date_created: Option<Direction>,

//     /// Sort by `date_published`.
//     pub date_published: Option<Direction>,

//     /// Sort by `message_timestamp`.
//     pub message_timestamp: Option<Direction>,
// }

// /// Sort direction.
// #[derive(Clone, Debug, Default, Deserialize, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub enum Direction {
//     /// Sort ascending.
//     #[default]
//     Ascending = 1,

//     /// Sort descending.
//     Descending = -1,
// }
