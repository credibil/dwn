//! # Event

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::Descriptor;

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

/// Used by the client to handle events subscribed to.
#[derive(Debug, Deserialize, Serialize)]
pub struct Subscriber {
    id: String,

    #[serde(skip)]
    receiver: Option<mpsc::Receiver<Event>>,
}

impl Default for Subscriber {
    fn default() -> Self {
        Self {
            id: Default::default(),
            receiver: None,
        }
    }
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
