use anyhow::Result;
use vercre_dwn::provider::MessageStore;
use vercre_dwn::service::Message;
use vercre_dwn::Cursor;

use super::ProviderImpl;
// use crate::keystore::OWNER_DID;
use crate::store::{NAMESPACE, PROTOCOL};

impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, message: Message) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Message> =
            self.db.create((PROTOCOL, message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Message>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        Ok(self.db.select((PROTOCOL, message_cid)).await?)
    }

    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<Message>, Cursor)> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let mut response = self.db.query(sql).await?;

        // TODO: sort and paginate
        Ok((response.take(0)?, Cursor::default()))
    }

    // async fn query(
    //     &self, owner: &str, filters: Vec<Filter>, sort: Option<Sort>,
    //     pagination: Option<Pagination>,
    // ) -> Result<(Vec<Message>, Cursor)> {
    //     self.db.use_ns(NAMESPACE).use_db(owner).await?;

    //     // build SQL-like statement
    //     let mut where_clause = " WHERE 1 = 1".to_string();
    //     for filter in filters {
    //         for (field, citerion) in filter.criteria {
    //             match citerion {
    //                 Criterion::Single(cmp) => {
    //                     match cmp {
    //                         Compare::Equal(val) => {
    //                             where_clause.push_str(&format!(" AND {} = {}", field, val));
    //                         }
    //                         _ => todo!("support other comparisons"),
    //                     };
    //                 }
    //                 Criterion::OneOf(values) => {
    //                     let _ = values;
    //                 }
    //                 Criterion::Range(range) => {
    //                     let _ = range;
    //                 }
    //             }
    //         }
    //     }
    //     where_clause = where_clause.replace('"', "'");

    //     let mut response = self
    //         .db
    //         .query("SELECT * FROM type::table($table)".to_owned() + &where_clause)
    //         .bind(("table", "protocol"))
    //         .await?;

    //     // TODO: sort and paginate
    //     // deserialize messages
    //     let mut messages = vec![];
    //     while let Some(msg) = response.take::<Option<Message>>(0)? {
    //         messages.push(msg);
    //     }

    //     Ok((messages, Cursor::default()))
    // }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<Message> = self.db.delete((PROTOCOL, message_cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        // self.db.use_ns(NAMESPACE);

        Ok(())
    }
}
