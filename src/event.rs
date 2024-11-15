//! # Event

use std::async_iter::AsyncIterator;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};

// use tokio::sync::mpsc;
use crate::messages::Filter;
use crate::{Descriptor, Result};

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
pub struct Listener<T> {
    /// Message filters for the subscription.
    pub filters: Vec<Filter>,

    pub receiver: Option<T>,

    /// The event handler.
    pub subscriber: Option<Subscriber>,
}

impl<T> Listener<T> {
    /// Event callback.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn push(&mut self, event: Event) -> Result<()> {
        // if owner == event_owner && FilterUtility.matchAnyFilter(eventIndexes, messagesFilters) {
        println!("event received: {event:?}");
        // }

        self.subscriber.as_mut().unwrap().send(event);

        Ok(())
    }
}

/// Used by the client to handle events subscribed to.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscriber {
    id: String,
    receiver: Vec<Event>,
}

impl Subscriber {
    /// Send an event to the subscriber.
    pub fn send(&mut self, event: Event) {
        self.receiver.push(event);
    }

    /// Closes the subscriber.
    pub fn close() {
        todo!()
    }
}

impl AsyncIterator for Subscriber {
    type Item = Event;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.receiver.iter().next().cloned())
        // Poll::Ready(Some(self.receiver.poll_recv(cx)))
        // Poll::Ready(None)
    }
}

// impl Stream for Subscriber {
//     type Item = Message;

//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         self.receiver.poll_recv(cx)
//     }
// }
