use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use dwn_node::event::Event;
use dwn_node::provider::{BlockStore, EventLog};
use dwn_node::store::{Cursor, Query, block, index};
use serde_json::Value;

use super::ProviderImpl;
use crate::provider::NAMESPACE;

const TABLE: &str = "event_log";

impl EventLog for ProviderImpl {
    async fn append(&self, owner: &str, event: &Event) -> Result<()> {
        // self.db.use_ns(NAMESPACE).use_db(owner).await?;
        // let _: Option<BTreeMap<String, Value>> =
        //     self.db.update((TABLE, event.cid()?)).content(event).await?;

        // store entry block
        let message_cid = event.cid()?;
        BlockStore::delete(self, owner, &message_cid).await?;
        BlockStore::put(self, owner, &message_cid, &block::encode(event)?).await?;

        // index entry
        // TODO: add watermark to indexes
        // const watermark = this.ulidFactory();
        Ok(index::insert(owner, &event, self).await?)
        // Ok(())
    }

    async fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> Result<(Vec<Event>, Option<Cursor>)> {
        todo!()
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Event>, Option<Cursor>)> {
        // self.db.use_ns(NAMESPACE).use_db(owner).await?;

        // let mut serializer = surrealdb::Sql::new();
        // query.serialize(&mut serializer).unwrap();
        // let sql = serializer.output();

        // let mut response = self.db.query(sql).bind(("table", TABLE)).await?;
        // let events: Vec<Event> = response.take(0)?;
        // Ok((events, Cursor::default()))

        // FIXME: sort and paginate

        let mut results = index::query(owner, query, self).await?;

        let (limit, cursor) = if let Query::Records(query) = query {
            query.pagination.as_ref().map_or((None, None), |p| (p.limit, p.cursor.as_ref()))
        } else {
            (None, None)
        };

        // return cursor when paging is used
        let limit = limit.unwrap_or_default();
        let cursor = if limit > 0 && limit < results.len() {
            let Query::Records(query) = query else {
                return Err(anyhow!("invalid query"));
            };
            let sort_field = query.sort.to_string();

            // set cursor to the last item remaining after the spliced result.
            results.pop().map_or(None, |item| {
                Some(Cursor {
                    message_cid: item.message_cid.clone(),
                    value: item.fields[&sort_field].clone(),
                })
            })
        } else {
            None
        };

        let mut entries = Vec::new();
        for item in results {
            let Some(bytes) = BlockStore::get(self, owner, &item.message_cid).await? else {
                return Err(anyhow!("missing block for message cid"));
            };
            entries.push(block::decode(&bytes)?)
        }

        Ok((entries, cursor))
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
