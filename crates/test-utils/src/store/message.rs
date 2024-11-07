use anyhow::Result;
use async_trait::async_trait;
use vercre_dwn::provider::MessageStore;
use vercre_dwn::{Cursor, Message};

use super::ProviderImpl;
use crate::store::{MESSAGE, NAMESPACE};

#[async_trait]
impl MessageStore for ProviderImpl {
    async fn put<T: Message>(&self, owner: &str, message: &T) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<T> = self.db.create((MESSAGE, message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn get<T: Message>(&self, owner: &str, message_cid: &str) -> Result<Option<T>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        Ok(self.db.select((MESSAGE, message_cid)).await?)
    }

    async fn query<T: Message>(&self, owner: &str, sql: &str) -> Result<(Vec<T>, Cursor)> {
        let sql = format!("SELECT * FROM message {sql}");
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let mut response = self.db.query(&sql).await?;
        let messages: Vec<T> = response.take(0)?;

        println!("SQL: {sql} for {owner}");
        println!("Messages: {}", messages.len());

        Ok((messages, Cursor::default()))

        // TODO: sort and paginate
        // Ok((response.take(0)?, Cursor::default()))
    }

    async fn delete<T: Message>(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<T> = self.db.delete((MESSAGE, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        // self.db.use_ns(NAMESPACE);

        Ok(())
    }
}
