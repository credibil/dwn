use anyhow::Result;
use vercre_dwn::provider::{Entry, MessageStore, Query};
use vercre_dwn::store::serializer::Serialize;
use vercre_serialize::surrealdb;

use super::ProviderImpl;
use crate::provider::NAMESPACE;
pub(crate) const TABLE: &str = "message";

impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, entry: &Entry) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        // let json = serde_json::to_string(entry)?;
        // println!("{json}\n");

        let _: Option<Entry> = self.db.update((TABLE, entry.cid()?)).content(entry).await?;
        Ok(())
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<Vec<Entry>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        let mut serializer = surrealdb::Sql::new();
        query.serialize(&mut serializer).unwrap();
        let sql = serializer.output();
        // println!("{sql}");
        let mut response = self.db.query(sql).bind(("table", TABLE)).await?;
        response.take(0).map_err(|e| e.into())
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Entry>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        Ok(self.db.select((TABLE, message_cid)).await?)
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Entry> = self.db.delete((TABLE, message_cid)).await?;
        Ok(())
    }

    // TODO: Implement purge
    async fn purge(&self) -> Result<()> {
        todo!("implement purge")
    }
}
