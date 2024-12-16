use anyhow::Result;
use async_trait::async_trait;
use vercre_dwn::provider::{Entry, MessageStore, Query};
use vercre_dwn::store::Cursor;
use vercre_serialize::{Serialize, surrealdb};

use super::ProviderImpl;
use crate::provider::NAMESPACE;
pub(crate) const TABLE: &str = "message";

#[async_trait]
impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, entry: &Entry) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Entry> = self.db.update((TABLE, entry.cid()?)).content(entry).await?;
        Ok(())
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Entry>, Cursor)> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;

        let mut serializer = surrealdb::Serializer::new();
        query.serialize(&mut serializer).unwrap();
        let sql = serializer.output();
        // println!("{sql}");

        let mut response = self.db.query(sql).bind(("table", TABLE)).await?;
        let entries: Vec<Entry> = response.take(0)?;

        Ok((entries, Cursor::default()))

        // let pagination = Some(Pagination::default());

        // // no pagination
        // let Some(pagination) = &pagination else {
        //     return Ok((entries, Cursor::default()));
        // };

        // pagination
        // let limit = pagination.limit.unwrap_or_default();
        // if limit < entries.len() {
        //     // remove last entry and set cursor to the second-to-last entry
        //     entries = entries.as_slice()[0..pagination.limit.unwrap_or_default()].to_vec();

        //     let last_entry = entries.last().unwrap();
        //     let message_cid = last_entry.cid()?;

        //     // value is the value from the field sorted on
        //     // let field = query.sort_on();
        //     // let value = last_entry.get(field).unwrap_or_default();

        //     return Ok((
        //         entries,
        //         Cursor {
        //             message_cid,
        //             sort_value: "".to_string(),
        //         },
        //     ));
        // }
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

    async fn purge(&self) -> Result<()> {
        // self.db.use_ns(NAMESPACE);
        Ok(())
    }
}
