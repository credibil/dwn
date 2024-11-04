use std::collections::BTreeMap;
use std::future::Future;

use anyhow::Result;
use serde_json::Value;
use vercre_dwn::provider::{Event, EventLog, EventStream, EventSubscription};
use vercre_dwn::query::Filter;
use vercre_dwn::{Cursor, Message};

use super::ProviderImpl;
use crate::store::NAMESPACE;

const DATABASE: &str = "event_log";

impl EventLog for ProviderImpl {
    async fn append(&self, owner: &str, message_cid: &str, message: &Message) -> Result<()> {
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

struct EventSubscriptionImpl;

impl EventSubscription for EventSubscriptionImpl {
    async fn close(&self) -> Result<()> {
        todo!()
    }
}

impl EventStream for ProviderImpl {
    /// Subscribes to a owner's event stream.
    fn subscribe(
        &self, owner: &str, id: &str, listener: impl Fn(&str, Event),
    ) -> impl Future<Output = Result<(String, impl EventSubscription)>> + Send {
        async { Ok((String::new(), EventSubscriptionImpl {})) }
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        // todo!()
        Ok(())
    }
}
