use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vercre_dwn::event::{Event, SubscribeFilter, Subscriber};
use vercre_dwn::provider::{EventLog, EventStream};
use vercre_dwn::store::{Cursor, Query};
use vercre_serialize::QuerySerializer;

use super::ProviderImpl;
use crate::store::NAMESPACE;

const TABLE: &str = "event_log";

#[async_trait]
impl EventLog for ProviderImpl {
    async fn append(&self, owner: &str, event: &Event) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> =
            self.db.create((TABLE, &event.message_cid)).content(event).await?;
        Ok(())
    }

    async fn events(&self, owner: &str, cursor: Option<Cursor>) -> Result<(Vec<Event>, Cursor)> {
        todo!()
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Event>, Cursor)> {
        let sql = query.serialize();
        let mut response = self.db.query(&sql).bind(("table", TABLE)).await?;
        let events: Vec<Event> = response.take(0)?;
        Ok((events, Cursor::default()))

        // TODO: sort and paginate
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> = self.db.delete((TABLE, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}

// pub struct SubscriberImpl {
//     pub id: String,
//     pub receiver: async_nats::Subscriber,
// }

// #[async_trait]
// impl EventSubscriber for SubscriberImpl {
//     async fn close(&self) -> Result<()> {
//         todo!()
//     }
// }

#[async_trait]
impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(
        &self, owner: &str, message_cid: &str, filters: SubscribeFilter,
    ) -> Result<Subscriber> {
        // set up subscriber
        let mut nats_subscriber = self.nats_client.subscribe("messages").await?;
        let (sender, receiver) = mpsc::channel::<Event>(100);

        // forward filtered messages from NATS to our subscriber
        let task: JoinHandle<Result<()>> = tokio::spawn(async move {
            while let Some(message) = nats_subscriber.next().await {
                let event: Event = serde_json::from_slice(&message.payload)?;
                sender.send(event).await?;
            }
            Ok(())
        });

        Ok(Subscriber::new(message_cid, receiver))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish("messages", bytes.into()).await?;
        Ok(())
    }
}
