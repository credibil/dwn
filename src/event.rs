//! # Event

use std::pin::Pin;
use std::task::{Context, Poll};

use chrono::{DateTime, Utc};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::messages::MessagesFilter;
use crate::records::{RecordsFilter, TagFilter};
use crate::store::{Entry, EntryType};

/// Alias for `store::Entry` used for event-related functionality.
pub type Event = Entry;

/// Alias for `store::EventType` to be used as the type of the event.
pub type EventType = EntryType;

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

    // Poll Tokio mpsc receiver for new events
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let event = self.receiver.as_mut().unwrap().poll_recv(cx);

        // check 'ready' events match the stream filter before surfacing it
        if let Poll::Ready(Some(event)) = &event {
            if self.filter.is_match(event) {
                return Poll::Ready(Some(event.clone()));
            }
            return Poll::Pending;
        }

        event
    }
}

impl SubscribeFilter {
    fn is_match(&self, event: &Event) -> bool {
        match self {
            Self::Messages(filters) => {
                for filter in filters {
                    if filter.is_match(event) {
                        return true;
                    }
                }
                false
            }
            Self::Records(filter) => {
                // when filter is record filter, check event is a record
                if let EventType::Configure(_) = event.message {
                    return false;
                }
                filter.is_match(event)
            }
        }
    }
}

impl RecordsFilter {
    #[allow(clippy::too_many_lines)]
    fn is_match(&self, event: &Entry) -> bool {
        let EventType::Write(write) = &event.message else {
            return false;
        };
        let indexes = &event.indexes;
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
        if let Some(tags) = &self.tags {
            for (property, filter) in tags {
                let Some(tags) = &descriptor.tags else {
                    return false;
                };
                let value = tags.get(property).unwrap_or(&Value::Null);
                if !filter.is_match(value) {
                    return false;
                }
            }
        }
        if let Some(data_format) = &self.data_format {
            if data_format != &descriptor.data_format {
                return false;
            }
        }
        if let Some(data_size) = &self.data_size {
            if !data_size.contains(&descriptor.data_size) {
                return false;
            }
        }
        if let Some(data_cid) = &self.data_cid {
            if data_cid != &descriptor.data_cid {
                return false;
            }
        }
        if let Some(date_created) = &self.date_created {
            if !date_created.contains(&descriptor.date_created) {
                return false;
            }
        }
        if let Some(date_published) = &self.date_published {
            if !date_published.contains(&descriptor.date_published.unwrap_or_default()) {
                return false;
            }
        }

        // `date_updated` is found in indexes
        if let Some(date_updated) = &self.date_updated {
            let Some(updated) = indexes.get("dateUpdated") else {
                return false;
            };
            let Some(updated) = updated.as_str() else {
                return false;
            };
            let Some(date) = updated.parse::<DateTime<Utc>>().ok() else {
                return false;
            };
            if !date_updated.contains(&date) {
                return false;
            }
        }

        true
    }
}

impl TagFilter {
    fn is_match(&self, tag: &Value) -> bool {
        match self {
            Self::StartsWith(value) => {
                let tag = tag.as_str().unwrap_or_default();
                tag.starts_with(value)
            }
            Self::Range(range) => {
                let tag = tag.as_u64().unwrap_or_default();
                range.contains(&usize::try_from(tag).unwrap_or_default())
            }
            Self::Equal(value) => tag == value,
        }
    }
}

impl MessagesFilter {
    fn is_match(&self, event: &Entry) -> bool {
        let descriptor = &event.descriptor();

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
            match event.message {
                EventType::Write(ref write) => {
                    if Some(protocol) != write.descriptor.protocol.as_ref() {
                        return false;
                    }
                }
                EventType::Delete(_) => {
                    return false;
                }
                EventType::Configure(ref configure) => {
                    if protocol != &configure.descriptor.definition.protocol {
                        return false;
                    }
                }
            }
        }
        if let Some(message_timestamp) = &self.message_timestamp {
            if !message_timestamp.contains(&descriptor.message_timestamp.unwrap_or_default()) {
                return false;
            }
        }

        true
    }
}
