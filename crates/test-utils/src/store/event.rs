use std::collections::BTreeMap;
use std::ops::Sub;

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;
use vercre_dwn::event::{Event, Listener, Subscriber};
use vercre_dwn::provider::{EventLog, EventStream, EventSubscriber};
use vercre_dwn::Cursor;

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

    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<Event>, Cursor)> {
        let sql = format!("SELECT * FROM {TABLE} {sql}");
        let mut response = self.db.query(&sql).await?;
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

pub struct SubscriberImpl {
    pub id: String,
}

#[async_trait]
impl EventSubscriber for SubscriberImpl {
    async fn close(&self) -> Result<()> {
        todo!()
    }
}

#[async_trait]
impl EventStream for ProviderImpl {
    type Subscriber = SubscriberImpl;

    /// Subscribe to a owner's event stream.
    async fn subscribe(
        &self, owner: &str, message_cid: &str, listener: &mut Listener,
    ) -> Result<Subscriber> {
        let mut nats_sub = self.nats_client.subscribe("subject").await?;

        while let Some(m) = nats_sub.next().await {
            let event: Event = serde_json::from_slice(&m.payload)?;
            let _ = listener.push(event)?;
        }

        todo!()
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        // todo!()
        Ok(())
    }
}
