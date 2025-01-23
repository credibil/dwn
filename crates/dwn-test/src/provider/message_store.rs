use anyhow::Result;
use dwn_node::provider::{BlockStore, Entry, MessageStore, Query};
use dwn_node::store::{block, index};

use super::ProviderImpl;

impl MessageStore for ProviderImpl {
    async fn put(&self, owner: &str, entry: &Entry) -> Result<()> {
        // store entry block
        let message_cid = entry.cid().unwrap();
        let block = block::encode(entry).unwrap();
        BlockStore::put(self, owner, &message_cid, &block).await.unwrap();

        // update indexes
        Ok(index::insert(owner, &entry, self).await?)
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<Vec<Entry>> {
        Ok(index::query(owner, query, self).await?)
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
