use anyhow::{Result, anyhow};
use dwn_node::provider::{BlockStore, Entry, MessageStore, Query};
use dwn_node::store::{Cursor, block, index};

use super::ProviderImpl;

impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, entry: &Entry) -> Result<()> {
        // store entry block
        let message_cid = entry.cid()?;

        // println!("putting message cid: {}", message_cid);

        BlockStore::delete(self, owner, &message_cid).await?;
        BlockStore::put(self, owner, &message_cid, &block::encode(entry)?).await?;
        Ok(index::insert(owner, &entry, self).await?)
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<Vec<Entry>> {
        let results = index::query(owner, query, self).await?;

        let mut entries = Vec::new();
        for item in results {
            let Some(bytes) = BlockStore::get(self, owner, &item.message_cid).await? else {
                return Err(anyhow!("missing block for message cid"));
            };
            entries.push(block::decode(&bytes)?)
        }

        Ok(entries)
    }

    async fn paginated_query(
        &self, owner: &str, query: &Query,
    ) -> Result<(Vec<Entry>, Option<Cursor>)> {
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

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Entry>> {
        let Some(bytes) = BlockStore::get(self, owner, message_cid).await? else {
            return Ok(None);
        };
        Ok(Some(block::decode(&bytes)?))
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        index::delete(owner, message_cid, self).await?;
        Ok(BlockStore::delete(self, owner, message_cid).await?)
    }

    // TODO: Implement purge
    async fn purge(&self) -> Result<()> {
        todo!("implement purge")
    }
}
