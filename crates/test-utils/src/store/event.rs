use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use vercre_dwn::provider::{Event, EventLog, EventStream, EventSubscription};
use vercre_dwn::query::Filter;
use vercre_dwn::{Cursor, Message};

use super::ProviderImpl;
use crate::store::NAMESPACE;

const DATABASE: &str = "event_log";

#[async_trait]
impl EventLog for ProviderImpl {
    async fn append<T: Message>(&self, owner: &str, message_cid: &str, message: &T) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> =
            self.db.create((DATABASE, message_cid)).content(message).await?;
        Ok(())
    }

    async fn events(&self, owner: &str, cursor: Option<Cursor>) -> Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn query(
        &self, owner: &str, filters: Vec<Filter>, cursor: Cursor,
    ) -> Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> = self.db.delete((DATABASE, message_cid)).await?;
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
