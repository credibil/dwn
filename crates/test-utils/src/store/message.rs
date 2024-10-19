use std::collections::BTreeMap;

use vercre_dwn::messages::Sort;
use vercre_dwn::provider::MessageStore;
use vercre_dwn::query::{Compare, Criterion, Filter};
use vercre_dwn::service::Message;
use vercre_dwn::{Cursor, Pagination};

use super::ProviderImpl;

impl MessageStore for ProviderImpl {
    async fn put(
        &self, tenant: &str, message: Message, _indexes: BTreeMap<&str, &str>,
    ) -> anyhow::Result<()> {
        self.db.use_ns("testing").use_db(tenant).await?;
        let _: Option<Message> =
            self.db.create(("message", message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn get(&self, tenant: &str, cid: &str) -> anyhow::Result<Option<Message>> {
        self.db.use_ns("testing").use_db(tenant).await?;
        Ok(self.db.select(("message", cid)).await?)
    }

    async fn query(
        &self, tenant: &str, filters: Vec<Filter>, sort: Option<Sort>,
        pagination: Option<Pagination>,
    ) -> anyhow::Result<(Vec<Message>, Cursor)> {
        self.db.use_ns("testing").use_db(tenant).await?;

        // build SQL-like statement
        let mut where_clause = " WHERE 1 = 1".to_string();

        for filter in filters {
            for (field, citerion) in filter.criteria {
                match citerion {
                    Criterion::Single(cmp) => {
                        match cmp {
                            Compare::Equal(val) => {
                                where_clause.push_str(&format!(" AND {} = {}", field, val));
                            }
                            _ => todo!("support other comparisons"),
                        };
                    }
                    Criterion::OneOf(values) => {
                        let _ = values;
                    }
                    Criterion::Range(range) => {
                        let _ = range;
                    }
                }
            }
        }

        where_clause = where_clause.replace('"', "'");

        let mut response = self
            .db
            .query("SELECT * FROM type::table($table)".to_owned() + &where_clause)
            .bind(("table", "protocol"))
            .await?;

        // TODO: sort and paginate
        // deserialize messages
        let mut messages = vec![];
        while let Some(msg) = response.take::<Option<Message>>(0)? {
            messages.push(msg);
        }

        Ok((messages, Cursor::default()))
    }

    async fn delete(&self, tenant: &str, cid: &str) -> anyhow::Result<()> {
        self.db.use_ns("testing").use_db(tenant).await?;
        let person: Option<Message> = self.db.delete(("message", cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> anyhow::Result<()> {
        // self.db.use_ns("testing");

        Ok(())
    }
}
