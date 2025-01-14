use std::collections::BTreeMap;

use anyhow::Result;
use serde_json::Value;
use vercre_dwn_server::event::Event;
use vercre_dwn_server::provider::EventLog;
use vercre_dwn_server::store::serializer::Serialize;
use vercre_dwn_server::store::{Cursor, Query};
use vercre_serialize::surrealdb;

use super::ProviderImpl;
use crate::provider::NAMESPACE;

const TABLE: &str = "event_log";

impl EventLog for ProviderImpl {
    async fn append(&self, owner: &str, event: &Event) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<BTreeMap<String, Value>> =
            self.db.update((TABLE, event.cid()?)).content(event).await?;
        Ok(())
    }

    async fn events(&self, owner: &str, cursor: Option<Cursor>) -> Result<(Vec<Event>, Cursor)> {
        todo!()
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Event>, Cursor)> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        let mut serializer = surrealdb::Sql::new();
        query.serialize(&mut serializer).unwrap();
        let sql = serializer.output();

        let mut response = self.db.query(sql).bind(("table", TABLE)).await?;
        let events: Vec<Event> = response.take(0)?;
        Ok((events, Cursor::default()))

        // FIXME: sort and paginate
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
