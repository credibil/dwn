//! # Event

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, stream};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Used by local clients to handle events subscribed to.
pub struct Subscriber {
    pub(crate) inner: Pin<Box<dyn Stream<Item = Event> + Send>>,
}

impl Subscriber {
    /// Wrap Provider's subscription Stream for ease of surfacing to users.
    #[must_use]
    pub fn new(stream: impl Stream<Item = Event> + Send + 'static) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }
}

impl Stream for Subscriber {
    type Item = Event;

    // Poll underlying stream for new events
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl Default for Subscriber {
    fn default() -> Self {
        Self {
            inner: Box::pin(stream::empty()),
        }
    }
}

impl fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscriber").finish()
    }
}

impl SubscribeFilter {
    /// Check the event matches the filter.
    #[must_use]
    pub fn is_match(&self, event: &Event) -> bool {
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

// TODO: move this close to RecordsFilter
impl RecordsFilter {
    /// Determine whether the specified `Entry` matches the filter.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    #[must_use]
    pub fn is_match(&self, event: &Entry) -> bool {
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
            if Some(&attester) != indexes.get("attester") {
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
            if *published != descriptor.published.unwrap_or_default() {
                return false;
            }
        }
        if let Some(context_id) = &self.context_id {
            if !write.context_id.as_ref().unwrap_or(&String::new()).starts_with(context_id) {
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
        if let Some(date_updated) = &self.date_updated {
            if !date_updated.contains(&descriptor.base.message_timestamp) {
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
            if !message_timestamp.contains(&descriptor.message_timestamp) {
                return false;
            }
        }

        true
    }
}
