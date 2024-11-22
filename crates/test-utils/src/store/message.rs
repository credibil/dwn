use anyhow::Result;
use async_trait::async_trait;
use vercre_dwn::provider::{MessageStore, Query, Record};
use vercre_dwn::store::QuerySerializer;
use vercre_dwn::Cursor;

use super::ProviderImpl;
use crate::store::NAMESPACE;
pub(crate) const TABLE: &str = "message";

#[async_trait]
impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, record: &Record) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Record> = self.db.create((TABLE, record.cid()?)).content(record).await?;
        Ok(())
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Record>, Cursor)> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        let sql = query.serialize();
        let mut response = self.db.query(sql).await?;
        let messages: Vec<Record> = response.take(0)?;

        Ok((messages, Cursor::default()))

        // TODO: sort and paginate
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Record>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        Ok(self.db.select((TABLE, message_cid)).await?)
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<()> = self.db.delete((TABLE, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        // self.db.use_ns(NAMESPACE);
        Ok(())
    }
}
