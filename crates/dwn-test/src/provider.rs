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
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use vercre_dwn::protocols::Configure;
use vercre_dwn::provider::{DidResolver, Document, MessageStore, Provider};

use self::key_store::{ALICE_DID, BOB_DID, KeyStoreImpl};

const NAMESPACE: &str = "integration-test";

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
    blockstore: InMemoryBlockstore<64>,
    pub nats_client: async_nats::Client,
    pub keystore: KeyStoreImpl,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns(NAMESPACE).use_db(ALICE_DID).await?;
        let blockstore = InMemoryBlockstore::<64>::new();
        let nats_client = async_nats::connect("demo.nats.io").await?;

        let provider = Self {
            db,
            blockstore,
            nats_client,
            keystore: KeyStoreImpl::new(),
        };

        // load base protocol configuration for Alice and Bob
        let bytes = include_bytes!("./provider/data/protocol.json");
        let configure: Configure = serde_json::from_slice(bytes).expect("should deserialize");
        MessageStore::put(&provider, ALICE_DID, &configure.clone().into()).await?;
        MessageStore::put(&provider, BOB_DID, &configure.into()).await?;

        Ok(provider)
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        if url == ALICE_DID {
            return serde_json::from_slice(include_bytes!("./provider/data/alice_did.json"))
                .map_err(|e| anyhow!(format!("issue deserializing document: {e}")));
        } else {
            return serde_json::from_slice(include_bytes!("./provider/data/bob_did.json"))
                .map_err(|e| anyhow!(format!("issue deserializing document: {e}")));
        }
    }
}
