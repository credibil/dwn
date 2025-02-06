#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod block_store;
mod event_stream;
pub mod keystore;

use anyhow::Result;
use blockstore::InMemoryBlockstore;
use dwn_node::provider::{
    DataStore, DidResolver, Document, EventLog, MessageStore, Provider, TaskStore,
};

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
impl DataStore for ProviderImpl {}
impl EventLog for ProviderImpl {}
impl TaskStore for ProviderImpl {}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        unimplemented!("DidResolver::resolve")
    }
}
