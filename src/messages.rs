//! # Messages

pub mod query;
pub mod read;
pub mod subscribe;

use serde::{Deserialize, Serialize};

pub use self::query::{Query, QueryBuilder, QueryReply};
pub use self::read::{Read, ReadBuilder, ReadReply};
pub use self::subscribe::{Subscribe, SubscribeBuilder, SubscribeReply};
use crate::{DateRange, Descriptor, Interface, Method, Result};

// pub type EventListener = fn(owner: &str, event: Event) -> Result<()>;

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

/// Event listener.
pub struct EventListener {
    /// The web node owner.
    pub owner: String,

    /// Message filters for the subscription.
    pub filters: Vec<Filter>,

    /// The event handler.
    pub handler: EventHandler,
}

impl EventListener {
    /// Event callback.
    pub fn on_event(&self, event: Event) -> Result<()> {
        // if owner == event_owner && FilterUtility.matchAnyFilter(eventIndexes, messagesFilters) {
        println!("event received: {:?}", event);
        self.handler.on_event(&event);
        // }

        Ok(())
    }
}

/// Used by the client to handle events subscribed to.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EventHandler {
    id: String,
}

impl EventHandler {
    /// Called by the event handler when a new event is received.
    pub fn on_event(&self, event: &Event) {
        println!("event received: {:?}", event);
    }

    /// Closes the subscription to the event stream.
    pub async fn close() {
        todo!()
    }
}

/// `Messages` filter.
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

// /// MessageType sort.
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
