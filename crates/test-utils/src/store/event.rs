use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use vercre_dwn::messages::Event;
use vercre_dwn::provider::{EventLog, EventStream, EventSubscription};
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

pub struct EventSubscriptionImpl;

#[async_trait]
impl EventSubscription for EventSubscriptionImpl {
    async fn close(&self) -> Result<()> {
        todo!()
    }
}

#[async_trait]
impl EventStream for ProviderImpl {
    type Subscriber = EventSubscriptionImpl;

    /// Subscribes to a owner's event stream.
    async fn subscribe(
        &self, owner: &str, id: &str, listener: impl Fn(&str, Event) + Send,
    ) -> Result<(String, Self::Subscriber)> {
        Ok((String::new(), EventSubscriptionImpl {}))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        // todo!()
        Ok(())
    }
}
