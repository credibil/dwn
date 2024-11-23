//! # Event

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::messages::MessagesFilter;
use crate::records::RecordsFilter;
use crate::store::Entry;


/// Unifying type for all events (which happens to be identical to `Entry`).
pub type Event = Entry;

/// Filter to use when subscribing to events.
#[allow(missing_docs)]
pub enum SubscribeFilter {
    Messages(Vec<MessagesFilter>),
    Records(RecordsFilter),
}

/// Used by the client to handle events subscribed to.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Subscriber {
    id: String,

    #[serde(skip)]
    receiver: Option<mpsc::Receiver<Event>>,
}

impl Clone for Subscriber {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            receiver: None,
        }
    }
}

impl Subscriber {
    /// Create a new subscriber.
    pub fn new(id: impl Into<String>, receiver: mpsc::Receiver<Event>) -> Self {
        Self {
            id: id.into(),
            receiver: Some(receiver),
        }
    }
}

impl Stream for Subscriber {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.as_mut().unwrap().poll_recv(cx)
    }
}
