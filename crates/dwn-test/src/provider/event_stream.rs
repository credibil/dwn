use anyhow::Result;
use async_trait::async_trait;
use futures::stream::StreamExt;
use vercre_dwn::event::{Event, Subscriber};
use vercre_dwn::provider::EventStream;

use crate::provider::ProviderImpl;

const SUBJECT: &str = "events";

#[async_trait]
impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(&self, owner: &str) -> Result<Subscriber> {
        let subscriber = self.nats_client.subscribe(format!("{SUBJECT}.{owner}")).await?;
        let mapped = subscriber.map(|m| serde_json::from_slice::<Event>(&m.payload).unwrap());
        Ok(Subscriber::new(mapped))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish(format!("{SUBJECT}.{owner}"), bytes.into()).await?;
        Ok(())
    }
}
