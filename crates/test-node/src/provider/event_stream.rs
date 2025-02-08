use anyhow::Result;
use dwn_node::event::{Event, Subscriber};
use dwn_node::provider::EventStream;
use futures::stream::StreamExt;

use crate::provider::ProviderImpl;

const SUBJECT: &str = "events";

impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(&self, owner: &str) -> Result<Subscriber> {
        let subscriber = self.nats_client.subscribe(format!("{SUBJECT}.{owner}")).await?;
        let stream = subscriber.map(|m| serde_json::from_slice::<Event>(&m.payload).unwrap());
        Ok(Subscriber::new(stream))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish(format!("{SUBJECT}.{owner}"), bytes.into()).await?;
        Ok(())
    }
}
