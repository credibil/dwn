use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vercre_dwn::event::{Event, SubscribeFilter, Subscriber};
use vercre_dwn::provider::EventStream;

use crate::provider::ProviderImpl;

// const SUBJECT: &str = "events";

#[async_trait]
impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(&self, owner: &str, filter: SubscribeFilter) -> Result<Subscriber> {
        let mut subscriber = self.nats_client.subscribe(format!("events.{owner}")).await?;
        let (sender, receiver) = mpsc::channel::<Event>(100);

        // forward filtered messages from NATS to our subscriber
        let task: JoinHandle<Result<()>> = tokio::spawn(async move {
            while let Some(message) = subscriber.next().await {
                let event: Event = serde_json::from_slice(&message.payload)?;
                sender.send(event).await?;
            }
            Ok(())
        });

        Ok(Subscriber::new(filter, receiver))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish(format!("events.{owner}"), bytes.into()).await?;
        Ok(())
    }
}
