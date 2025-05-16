//! # Example Provider
//!
//! This example implements a simple in-memory provider for the Credibil DWN.
//! It uses an in-memory blockstore and a NATS client for message transport.

#![allow(dead_code)]

use std::sync::Arc;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use cid::Cid;
use credibil_dwn::event::{Event, Subscriber};
use credibil_dwn::provider::{BlockStore, EventStream, Identity, IdentityResolver};
use futures::stream::StreamExt;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

const RAW: u64 = 0x55;

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

#[derive(Serialize, Deserialize)]
struct Identitifier<'a> {
    owner: &'a str,
    partition: &'a str,
    key: &'a str,
}

impl<'a> Identitifier<'a> {
    fn new(owner: &'a str, partition: &'a str, key: &'a str) -> Self {
        Self {
            owner,
            partition,
            key,
        }
    }

    fn to_cid(&self) -> anyhow::Result<Cid> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash))
    }
}

impl BlockStore for ProviderImpl {
    async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        self.blockstore.put_keyed(&cid, block).await.map_err(Into::into)
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        let Some(bytes) = self.blockstore.get(&cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let cid = Identitifier::new(owner, partition, key).to_cid()?;
        self.blockstore.remove(&cid).await?;
        Ok(())
    }

    async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}

impl IdentityResolver for ProviderImpl {
    async fn resolve(&self, _url: &str) -> Result<Identity> {
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
