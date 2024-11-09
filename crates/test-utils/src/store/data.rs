use std::io::{Cursor, Read};
use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use blockstore::block::{Block, CidError};
use blockstore::{Blockstore, InMemoryBlockstore};
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use vercre_dwn::provider::DataStore;

use super::ProviderImpl;
use crate::store::{DATA, NAMESPACE};

const RAW_CODEC: u64 = 0x55;

struct RawBlock(Vec<u8>);

impl Block<64> for RawBlock {
    fn cid(&self) -> Result<Cid, CidError> {
        let hash = Code::Sha2_256.digest(&self.0);
        Ok(Cid::new_v1(RAW_CODEC, hash))
    }

    fn data(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[async_trait]
impl DataStore for ProviderImpl {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, mut data: impl Read + Send,
    ) -> Result<()> {
        let mut buffer = Vec::new();
        data.read_to_end(&mut buffer)?;
        let block = RawBlock(buffer);

        self.blockstore.put(block).await?;

        Ok(())
    }

    async fn get(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<Option<Vec<u8>>> {
        let cid = Cid::from_str(data_cid)?;

        let block = self.blockstore.get(&cid).await.unwrap();
        let block = block.unwrap();

        Ok(Some(block))
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}
