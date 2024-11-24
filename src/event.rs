//! # Event

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::messages::MessagesFilter;
use crate::records::RecordsFilter;
use crate::store::{Entry, EntryType};

/// Unifying type for all events (which happens to be identical to `Entry`).
pub type Event = Entry;

/// Filter to use when subscribing to events.
#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum SubscribeFilter {
    Messages(Vec<MessagesFilter>),
    Records(RecordsFilter),
}

impl Default for SubscribeFilter {
    fn default() -> Self {
        Self::Messages(Vec::default())
    }
}

/// Used by the client to handle events subscribed to.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Subscriber {
    filter: SubscribeFilter,

    #[serde(skip)]
    receiver: Option<mpsc::Receiver<Event>>,
}

impl Clone for Subscriber {
    fn clone(&self) -> Self {
        Self {
            filter: SubscribeFilter::default(),
            receiver: None,
        }
    }
}

impl Subscriber {
    /// Create a new subscriber.
    #[must_use]
    pub const fn new(filter: SubscribeFilter, receiver: mpsc::Receiver<Event>) -> Self {
        Self {
            filter,
            receiver: Some(receiver),
        }
    }
}

impl Stream for Subscriber {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let event = self.receiver.as_mut().unwrap().poll_recv(cx);

        if let Poll::Ready(Some(entry)) = &event {
            if self.filter.is_match(entry) {
                return Poll::Ready(Some(entry.clone()));
            }
        }
        event
    }
}

impl SubscribeFilter {
    fn is_match(&self, entry: &Entry) -> bool {
        match self {
            Self::Messages(filters) => {
                for filter in filters {
                    if filter.is_match(entry) {
                        return true;
                    }
                }
                false
            }
            Self::Records(filter) => filter.is_match(entry),
        }
    }
}

impl RecordsFilter {
    fn is_match(&self, entry: &Entry) -> bool {
        let EntryType::Write(write) = &entry.message else {
            return false;
        };
        let indexes = &entry.indexes;
        let descriptor = &write.descriptor;

        if let Some(author) = &self.author {
            if !author.to_vec().contains(&write.authorization.author().unwrap_or_default()) {
                return false;
            }
        }
        if let Some(attester) = self.attester.clone() {
            if Some(&Value::String(attester)) != indexes.get("attester") {
                return false;
            }
        }
        if let Some(recipient) = &self.recipient {
            if !recipient.to_vec().contains(descriptor.recipient.as_ref().unwrap_or(&String::new()))
            {
                return false;
            }
        }
        if let Some(protocol) = &self.protocol {
            if Some(protocol) != descriptor.protocol.as_ref() {
                return false;
            }
        }
        if let Some(protocol_path) = &self.protocol_path {
            if Some(protocol_path) != descriptor.protocol_path.as_ref() {
                return false;
            }
        }
        if let Some(published) = &self.published {
            if Some(published) != descriptor.published.as_ref() {
                return false;
            }
        }
        if let Some(context_id) = &self.context_id {
            if Some(context_id) != write.context_id.as_ref() {
                return false;
            }
        }
        if let Some(schema) = &self.schema {
            if Some(schema) != descriptor.schema.as_ref() {
                return false;
            }
        }
        if let Some(record_id) = &self.record_id {
            if record_id != &write.record_id {
                return false;
            }
        }
        if let Some(parent_id) = &self.parent_id {
            if Some(parent_id) != descriptor.parent_id.as_ref() {
                return false;
            }
        }

        // if let Some(tags) = &self.tags {
        //     if Some(tags) != descriptor.tags.as_ref() {
        //         return false;
        //     }
        // }
        if let Some(data_format) = &self.data_format {
            if data_format != &descriptor.data_format {
                return false;
            }
        }
        // if let Some(data_size) = &self.data_size {
        //     if data_size != descriptor.data_size {
        //         return false;
        //     }
        // }
        if let Some(data_cid) = &self.data_cid {
            if data_cid != &descriptor.data_cid {
                return false;
            }
        }
        // if let Some(date_created) = &self.date_created {
        //     if Some(date_created) != descriptor.date_created.as_ref() {
        //         return false;
        //     }
        // }
        // if let Some(date_published) = &self.date_published {
        //     if Some(date_published) != descriptor.date_published.as_ref() {
        //         return false;
        //     }
        // }
        // if let Some(date_updated) = &self.date_updated {
        //     if Some(date_updated) != descriptor.date_updated.as_ref() {
        //         return false;
        //     }
        // }

        true
    }
}

impl MessagesFilter {
    fn is_match(&self, entry: &Entry) -> bool {
        let descriptor = &entry.descriptor();

        if let Some(interface) = &self.interface {
            if interface != &descriptor.interface {
                return false;
            }
        }
        if let Some(method) = &self.method {
            if method != &descriptor.method {
                return false;
            }
        }
        if let Some(protocol) = &self.protocol {
            match entry.message {
                EntryType::Write(ref write) => {
                    if Some(protocol) != write.descriptor.protocol.as_ref() {
                        return false;
                    }
                }
                EntryType::Delete(_) => {
                    return false;
                }
                EntryType::Configure(ref configure) => {
                    if protocol != &configure.descriptor.definition.protocol {
                        return false;
                    }
                }
            }
        }

        // if let Some(message_timestamp) = &self.message_timestamp {
        //     if Some(message_timestamp) != descriptor.message_timestamp.as_ref() {
        //         return false;
        //     }
        // }

        true
    }
}
