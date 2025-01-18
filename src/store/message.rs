

#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::Result;

use crate::provider::{BlockStore, Entry, MessageStore, Query};
use crate::store::block;

struct Store<'a, T: BlockStore> {
    block_store: &'a T,
}

impl<'a, T: BlockStore> Store<'a, T> {
    pub fn new(block_store: &'a T) -> Self {
        Self { block_store }
    }
}

impl<T: BlockStore> MessageStore for Store<'_, T> {
     async fn put(&self, owner: &str, entry: &Entry) -> Result<()> {
        // store indexes
        // let indexes = &entry.indexes;

        // store entry as IPLD block(s)
        let block = block::encode(entry).unwrap();
        self.block_store.put(owner, &block.cid().to_string(), block.data()).await?;

        Ok(())
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<Vec<Entry>> {
        // query index for matching entries

        // fetch entries from block store by CID

        todo!()
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Entry>> {
        todo!()
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        todo!()
    }

    // TODO: Implement purge
    async fn purge(&self) -> Result<()> {
        todo!("implement purge")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use blockstore::{Blockstore as _, InMemoryBlockstore};
    use dwn_test::key_store::{self, ALICE_DID};
    // use ipld_core::ipld;
    // use ipld_core::ipld::Ipld;
    use rand::RngCore;
    use serde_json::json;

    use super::*;
    use crate::clients::records::{Data, WriteBuilder};
    use crate::data::{DataStream, MAX_ENCODED_SIZE};
    use crate::store::{EntryType, block};

    #[tokio::test]
    async fn test_store() {
        let alice_signer = key_store::signer(ALICE_DID);

        let block_store = BlockStoreImpl::new();
        let store = Store::new(&block_store);

        let mut data = [0u8; MAX_ENCODED_SIZE + 10];
        rand::thread_rng().fill_bytes(&mut data);
        let stream = DataStream::from(data.to_vec());

        let write = WriteBuilder::new()
            .data(Data::Stream(stream.clone()))
            .sign(&alice_signer)
            .build()
            .await
            .unwrap();

        let indexes = json!({
            "key": "value",
        });

        let entry = Entry {
            message: EntryType::Write(write),
            indexes: indexes.as_object().unwrap().clone(),
        };

        store.put("owner", &entry).await.unwrap();
    }

    #[tokio::test]
    async fn test_ipld() {
        let alice_signer = key_store::signer(ALICE_DID);

        let write = WriteBuilder::new().sign(&alice_signer).build().await.unwrap();
        let block = block::encode(&write).unwrap();
        println!("{:?}", block.cid());
    }

    struct BlockStoreImpl {
        blockstore: InMemoryBlockstore<64>,
    }

    impl BlockStoreImpl {
        pub fn new() -> Self {
            Self {
                blockstore: InMemoryBlockstore::<64>::new(),
            }
        }
    }

    impl BlockStore for BlockStoreImpl {
        async fn put(&self, owner: &str, cid: &str, data: &[u8]) -> Result<()> {
            // HACK: convert libipld CID to blockstore CID
            let block_cid = cid::Cid::from_str(cid)?;
            self.blockstore.put_keyed(&block_cid, data).await.map_err(Into::into)
        }

        async fn get(&self, owner: &str, cid: &str) -> Result<Option<Vec<u8>>> {
            // HACK: convert libipld CID to blockstore CID
            let block_cid = cid::Cid::try_from(cid)?;
            let Some(bytes) = self.blockstore.get(&block_cid).await? else {
                return Ok(None);
            };
            Ok(Some(bytes))
        }

        async fn delete(&self, owner: &str, cid: &str) -> Result<()> {
            let cid = cid::Cid::from_str(cid)?;
            self.blockstore.remove(&cid).await?;
            Ok(())
        }

        async fn purge(&self) -> Result<()> {
            unimplemented!()
        }
    }
}
