//! # Example Provider
//!
//! This example implements a simple in-memory provider for the Credibil DWN.
//! It uses an in-memory blockstore and a NATS client for message transport.

#![allow(dead_code)]

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use credibil_dwn::event::{Event, Subscriber};
use credibil_dwn::provider::{BlockStore, DidDocument, DidResolver, EventStream};
use futures::stream::StreamExt;

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

impl BlockStore for ProviderImpl {
    async fn put(&self, _owner: &str, _partition: &str, cid: &str, block: &[u8]) -> Result<()> {
        // convert libipld CID to blockstore CID
        let block_cid = cid::Cid::from_str(cid)?;
        self.blockstore.put_keyed(&block_cid, block).await.map_err(Into::into)
    }

    async fn get(&self, _owner: &str, _partition: &str, cid: &str) -> Result<Option<Vec<u8>>> {
        // convert libipld CID to blockstore CID
        let block_cid = cid::Cid::try_from(cid)?;
        let Some(bytes) = self.blockstore.get(&block_cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    async fn delete(&self, _owner: &str, _partition: &str, cid: &str) -> Result<()> {
        let cid = cid::Cid::from_str(cid)?;
        self.blockstore.remove(&cid).await?;
        Ok(())
    }

    async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, _url: &str) -> Result<DidDocument> {
        unimplemented!("DidResolver::resolve")
    }
}

const SUBJECT: &str = "events";

impl EventStream for ProviderImpl {
    /// Subscribe to a owner's event stream.
    async fn subscribe(&self, owner: &str) -> Result<Subscriber> {
        let subscriber = self.nats_client.subscribe(format!("{SUBJECT}.{owner}")).await?;
        let mapped = subscriber.map(|m| serde_json::from_slice::<Event>(&m.payload).unwrap());
        Ok(Subscriber::new(mapped))
    }

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        self.nats_client.publish(format!("{SUBJECT}.{owner}"), bytes.into()).await?;
        Ok(())
    }
}
