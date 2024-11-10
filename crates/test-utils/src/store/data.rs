use std::io::Read;
use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use blockstore::block::{Block, CidError};
use blockstore::Blockstore;
use cid::Cid;
// use multihash_codetable::{Code, MultihashDigest};
use vercre_dwn::provider::DataStore;

use super::ProviderImpl;

// const RAW_CODEC: u64 = 0x55;
// const DATA: &str = "data";

struct RawBlock<'a>(&'a str, Vec<u8>);

impl<'a> Block<64> for RawBlock<'a> {
    fn cid(&self) -> Result<Cid, CidError> {
        // let hash = Code::Sha2_256.digest(&self.1);
        // Ok(Cid::new_v1(RAW_CODEC, hash))
        Ok(Cid::from_str(self.0).unwrap())
    }

    fn data(&self) -> &[u8] {
        self.1.as_ref()
    }
}

#[async_trait]
impl DataStore for ProviderImpl {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, mut data: impl Read + Send,
    ) -> Result<()> {
        let mut buffer = Vec::new();
        data.read_to_end(&mut buffer)?;
        let block = RawBlock(data_cid, buffer);

        self.blockstore.put(block).await?;

        Ok(())
    }

    async fn get(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<Option<Vec<u8>>> {
        let cid = Cid::from_str(data_cid)?;
        self.blockstore.get(&cid).await.map_err(|e| e.into())
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}
