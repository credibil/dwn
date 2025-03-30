//! # Example Provider
//!
//! This example implements a simple in-memory provider for the Credibil DWN.
//! It uses an in-memory blockstore and a NATS client for message transport.

#![allow(dead_code)]

mod block_store;
mod event_stream;

use std::sync::Arc;

use anyhow::Result;
use blockstore::InMemoryBlockstore;
use credibil_dwn::provider::{
    DataStore, DidDocument, DidResolver, EventLog, MessageStore, Provider, TaskStore,
};

#[derive(Clone)]
pub struct ProviderImpl {
    blockstore: Arc<InMemoryBlockstore<64>>,
    pub nats_client: Arc<async_nats::Client>,
}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            blockstore: Arc::new(InMemoryBlockstore::<64>::new()),
            nats_client: Arc::new(async_nats::connect("demo.nats.io").await?),
        })
    }
}

impl Provider for ProviderImpl {}
impl MessageStore for ProviderImpl {}
impl DataStore for ProviderImpl {}
impl EventLog for ProviderImpl {}
impl TaskStore for ProviderImpl {}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, _url: &str) -> Result<DidDocument> {
        unimplemented!("DidResolver::resolve")
    }
}
