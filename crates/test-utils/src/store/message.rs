use anyhow::Result;
use async_trait::async_trait;
use vercre_dwn::provider::MessageStore;
use vercre_dwn::service::MessageRecord;
use vercre_dwn::Cursor;

use super::ProviderImpl;
use crate::store::NAMESPACE;
pub(crate) const TABLE: &str = "message";

#[async_trait]
impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, message: &MessageRecord) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<MessageRecord> =
            self.db.create((TABLE, message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<MessageRecord>, Cursor)> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        let sql = format!("SELECT * FROM {TABLE} {sql}");
        let mut response = self.db.query(&sql).await?;
        let messages: Vec<MessageRecord> = response.take(0)?;
        Ok((messages, Cursor::default()))

        // TODO: sort and paginate
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<MessageRecord>> {
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
