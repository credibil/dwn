#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod block_store;
pub mod event_log;
mod event_stream;
pub mod key_store;
pub mod message_store;
pub mod task_store;

use anyhow::{Result, anyhow};
use blockstore::InMemoryBlockstore;
use dwn_node::provider::{DidResolver, Document, Provider};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

use self::key_store::ALICE_DID;

const NAMESPACE: &str = "integration-test";

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
    blockstore: InMemoryBlockstore<64>,
    pub nats_client: async_nats::Client,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns(NAMESPACE).use_db(ALICE_DID).await?;

        Ok(Self {
            db,
            blockstore: InMemoryBlockstore::<64>::new(),
            nats_client: async_nats::connect("demo.nats.io").await?,
        })
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        if url == ALICE_DID {
            serde_json::from_slice(include_bytes!("./provider/data/alice_did.json"))
                .map_err(|e| anyhow!(format!("issue deserializing document: {e}")))
        } else {
            serde_json::from_slice(include_bytes!("./provider/data/bob_did.json"))
                .map_err(|e| anyhow!(format!("issue deserializing document: {e}")))
        }
    }
}
