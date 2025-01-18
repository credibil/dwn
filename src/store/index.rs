//! # Index Store
//!
//! The index store is responsible for storing and retrieving message indexes.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::BTreeMap;

use anyhow::Result;
use ipld_core::codec::Codec;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;
use serde_json::{Map, Value};

use crate::provider::BlockStore;
use crate::store::block;

// #[derive(Debug)]

pub async fn put(
    owner: &str, message_cid: &str, values: &Map<String, Value>, store: &impl BlockStore,
) -> Result<()> {
    let mut indexes = IndexesBuilder::new().owner(owner).store(store).build().await?;

    println!("before: {:?}", indexes.inner);

    for (field, value) in values {
        let mut index = indexes.get(field).await?;
        index.insert(value.to_string(), message_cid);
        indexes.update(index).await?;
    }

    println!("after: {:?}", indexes.inner);

    Ok(())
}

pub struct Indexes<'a, S: BlockStore> {
    owner: &'a str,
    inner: BTreeMap<String, String>,
    store: &'a S,
}

impl<S: BlockStore> Indexes<'_, S> {
    // pub fn builder() -> IndexesBuilder<NoOwner, NoStore> {
    //     IndexesBuilder::new()
    // }

    pub fn cid(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Cid(String);
        block::compute_cid(&Cid(self.owner.to_string()))
    }

    pub async fn get(&mut self, field: &str) -> Result<Index> {
        let index_data = if let Some(index_cid) = self.inner.get(field) {
            let index_data = self.store.get(&self.owner, index_cid).await?.unwrap();
            let index_data: Index = DagCborCodec::decode_from_slice(&index_data)?;
            index_data
        } else {
            let index = Index {
                field: field.to_string(),
                values: BTreeMap::new(),
            };
            let index_cid = index.cid()?;

            let block = block::encode(&index)?;
            self.store.put(&self.owner, &index_cid, &block.data()).await?;

            self.inner.insert(field.to_string(), index_cid);

            let indexes_block = block::encode(&self.inner)?;
            self.store.put(&self.owner, &self.cid()?, &indexes_block.data()).await?;
            index
        };

        Ok(index_data)
    }

    pub async fn update(&mut self, index: Index) -> Result<()> {
        let index_cid = index.cid()?;

        self.store.delete(&self.owner, &index_cid).await?;
        self.store.put(&self.owner, &index_cid, &block::encode(&index)?.data()).await?;
        self.inner.insert(index.field, index_cid);

        // save the updated indexes block
        let indexes_block = block::encode(&self.inner)?;
        self.store.delete(&self.owner, &self.cid()?).await?;
        self.store.put(&self.owner, &self.cid()?, &indexes_block.data()).await?;

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Index {
    field: String,
    values: BTreeMap<String, String>,
}

impl Index {
    pub fn new(field: String) -> Self {
        Self {
            field,
            values: BTreeMap::new(),
        }
    }

    pub fn cid(&self) -> Result<String> {
        block::compute_cid(&Self {
            field: self.field.clone(),
            values: BTreeMap::new(),
        })
    }

    pub fn insert(&mut self, value: impl Into<String>, message_cid: impl Into<String>) {
        self.values.insert(value.into(), message_cid.into());
    }
}

pub struct IndexesBuilder<O, S> {
    owner: O,
    indexes: Option<BTreeMap<String, String>>,
    store: S,
}

/// Store not set on IndexesBuilder.
#[doc(hidden)]
pub struct NoOwner;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
pub struct Owner<'a>(&'a str);

/// Store not set on IndexesBuilder.
#[doc(hidden)]
pub struct NoStore;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
pub struct Store<'a, S: BlockStore>(&'a S);

impl IndexesBuilder<NoOwner, NoStore> {
    pub fn new() -> Self {
        Self {
            owner: NoOwner,
            indexes: None,
            store: NoStore,
        }
    }
}

impl<S> IndexesBuilder<NoOwner, S> {
    pub fn owner(self, owner: &str) -> IndexesBuilder<Owner, S> {
        IndexesBuilder {
            owner: Owner(owner),
            indexes: None,
            store: self.store,
        }
    }
}

impl<O> IndexesBuilder<O, NoStore> {
    pub fn store<S: BlockStore>(self, store: &S) -> IndexesBuilder<O, Store<'_, S>> {
        IndexesBuilder {
            owner: self.owner,
            indexes: self.indexes,
            store: Store(store),
        }
    }
}

impl<'a, S: BlockStore> IndexesBuilder<Owner<'a>, Store<'a, S>> {
    pub async fn build(self) -> Result<Indexes<'a, S>> {
        let mut indexes = Indexes {
            owner: self.owner.0,
            inner: BTreeMap::new(),
            store: self.store.0,
        };

        let indexes_cid = indexes.cid()?;

        indexes.inner = if let Some(bytes) = self.store.0.get(&indexes.owner, &indexes_cid).await? {
            DagCborCodec::decode_from_slice(&bytes)?
        } else {
            BTreeMap::new()
        };

        Ok(indexes)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use blockstore::{Blockstore as _, InMemoryBlockstore};
    use dwn_test::key_store::ALICE_DID;
    use serde_json::json;

    use super::*;
    // use crate::clients::records::WriteBuilder;
    // use crate::data::MAX_ENCODED_SIZE;
    // use crate::store::block;

    #[tokio::test]
    async fn test_put() {
        let block_store = BlockStoreImpl::new();

        let indexes = json!({
            "message_timestamp": "2025-01-01T00:00:00-00:00",
            "published": "true",
        });

        put(ALICE_DID, "message_cid_1", &indexes.as_object().unwrap(), &block_store).await.unwrap();
        put(ALICE_DID, "message_cid_2", &indexes.as_object().unwrap(), &block_store).await.unwrap();
    }

    // #[tokio::test]
    // async fn test_ipld() {
    //     let alice_signer = key_store::signer(ALICE_DID);

    //     let write = WriteBuilder::new().sign(&alice_signer).build().await.unwrap();
    //     let block = block::encode(&write).unwrap();
    //     println!("{:?}", block.cid());
    // }

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
