use std::collections::BTreeMap;

use serde_json::Value;
use vercre_dwn::provider::EventLog;
use vercre_dwn::query::Filter;
use vercre_dwn::Cursor;

use super::ProviderImpl;

impl EventLog for ProviderImpl {
    async fn append(
        &self, tenant: &str, message_cid: &str, indexes: BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        todo!()
    }

    async fn events(tenant: &str, cursor: Option<Cursor>) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn query_events(
        tenant: &str, filters: Vec<Filter>, cursor: Cursor,
    ) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn delete_events(tenant: &str, message_cids: Vec<&str>) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!()
    }
}
