//! # In-Memory Datastore

use std::sync::LazyLock;

use anyhow::Result;
// use credibil_core::datastore::Datastore;
use credibil_ecc::Vault;
use dashmap::DashMap;

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct Datastore;

impl Datastore {
    pub async fn put(owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.insert(key, data.to_vec());
        Ok(())
    }

    pub async fn get(owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = STORE.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    pub async fn delete(owner: &str, partition: &str, key: &str) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.remove(&key);
        Ok(())
    }

    pub async fn get_all(owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let all = STORE
            .iter()
            .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
            .map(|r| (r.key().to_string(), r.value().clone()))
            .collect::<Vec<_>>();
        Ok(all)
    }
}

#[derive(Clone, Debug)]
pub struct KeyVault;

impl Vault for KeyVault {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        Datastore::put(owner, partition, key, data).await
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Datastore::get(owner, partition, key).await
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        Datastore::delete(owner, partition, key).await
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        Datastore::get_all(owner, partition).await
    }
}
