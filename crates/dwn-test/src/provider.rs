#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod block_store;

mod event_stream;
pub mod key_store;

use anyhow::{Result, anyhow};
use blockstore::InMemoryBlockstore;
use dwn_node::provider::{DidResolver, Document, EventLog, MessageStore, Provider, TaskStore};

use self::key_store::ALICE_DID;

#[derive(Clone)]
pub struct ProviderImpl {
    blockstore: InMemoryBlockstore<64>,
    pub nats_client: async_nats::Client,
}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            blockstore: InMemoryBlockstore::<64>::new(),
            nats_client: async_nats::connect("demo.nats.io").await?,
        })
    }
}

impl Provider for ProviderImpl {}
impl MessageStore for ProviderImpl {}
impl EventLog for ProviderImpl {}
impl TaskStore for ProviderImpl {}

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
