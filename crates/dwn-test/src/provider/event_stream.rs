use anyhow::Result;
use async_trait::async_trait;
use futures::future;
use futures::stream::StreamExt;
// use tokio::sync::mpsc;
// use tokio::task::JoinHandle;
use vercre_dwn::event::{Event, SubscribeFilter, Subscriber};
use vercre_dwn::provider::EventStream;

use crate::provider::ProviderImpl;

// const SUBJECT: &str = "events";

#[async_trait]
impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(&self, owner: &str, filter: SubscribeFilter) -> Result<Subscriber> {
        let subscriber = self.nats_client.subscribe(format!("events.{owner}")).await?;
        let filtered = subscriber
            .map(|message| serde_json::from_slice::<Event>(&message.payload).unwrap())
            .filter(move |event| future::ready(filter.is_match(&event)));
        Ok(Subscriber::new(filtered.boxed()))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish(format!("events.{owner}"), bytes.into()).await?;
        Ok(())
    }
}
