use std::collections::BTreeMap;

use serde_json::Value;
use vercre_dwn::provider::EventLog;
use vercre_dwn::query::Filter;
use vercre_dwn::Cursor;

use super::ProviderImpl;
use crate::store::NAMESPACE;

const DATABASE: &str = "event_log";

impl EventLog for ProviderImpl {
    async fn append(
        &self, owner: &str, message_cid: &str, indexes: BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> =
            self.db.create((DATABASE, message_cid)).content(indexes).await?;
        Ok(())
    }

    async fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn query(
        &self, owner: &str, filters: Vec<Filter>, cursor: Cursor,
    ) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> anyhow::Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> = self.db.delete((DATABASE, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!()
    }
}
