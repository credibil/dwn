#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod block;
pub mod event;
pub mod message;
pub mod task;

use anyhow::{anyhow, Result};
use blockstore::InMemoryBlockstore;
use serde::Deserialize;
use surrealdb::engine::local::{Db, Mem};
use surrealdb::opt::RecordId;
use surrealdb::Surreal;
use vercre_dwn::protocols::Configure;
use vercre_dwn::provider::{DidResolver, Document, MessageStore, Provider};

use crate::keystore::{KeystoreImpl, ALICE_DID, BOB_DID};

const NAMESPACE: &str = "integration-test";

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
    blockstore: InMemoryBlockstore<64>,
    nats_client: async_nats::Client,
    pub keystore: KeystoreImpl,
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
            keystore: KeystoreImpl::new(),
        };

        // load base protocol configuration for Alice and Bob
        let bytes = include_bytes!("./store/protocol.json");
        let config: Configure = serde_json::from_slice(bytes).expect("should deserialize");
        MessageStore::put(&provider, ALICE_DID, &config.clone().into()).await?;
        MessageStore::put(&provider, BOB_DID, &config.into()).await?;

        Ok(provider)
    }
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[allow(dead_code)]
    id: RecordId,
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        serde_json::from_slice(include_bytes!("./store/did.json"))
            .map_err(|e| anyhow!(format!("issue deserializing document: {e}")))
    }
}
