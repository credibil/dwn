use anyhow::Result;
use vercre_dwn::provider::MessageStore;
use vercre_dwn::service::Message;
use vercre_dwn::Cursor;

use super::ProviderImpl;
use crate::store::{MESSAGE, NAMESPACE};

impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, message: &Message) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Message> = self.db.create((MESSAGE, message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Message>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        Ok(self.db.select((MESSAGE, message_cid)).await?)
    }

    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<Message>, Cursor)> {
        let sql = format!("SELECT * FROM message {sql}");
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let mut response = self.db.query(&sql).await?;
        let messages: Vec<Message> = response.take(0)?;

        println!("SQL: {sql} for {owner}");
        println!("Messages: {}", messages.len());

        Ok((messages, Cursor::default()))

        // TODO: sort and paginate
        // Ok((response.take(0)?, Cursor::default()))
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Message> = self.db.delete((MESSAGE, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        // self.db.use_ns(NAMESPACE);

        Ok(())
    }
}
