//! # Mock Provider

use std::sync::Arc;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use cid::Cid;
use credibil_core::api::Client;
use credibil_dwn::event::{Event, Subscriber};
use credibil_dwn::provider::{BlockStore, EventStream, Resolver};
use credibil_proof::DocumentRequest;
use futures::stream::StreamExt;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

use crate::store::Store;

const RAW: u64 = 0x55;
const SUBJECT: &str = "events";
#[derive(Clone)]
pub struct Provider {
    blockstore: Arc<InMemoryBlockstore<64>>,
    pub nats_client: Arc<async_nats::Client>,
}

impl Provider {
    pub async fn new() -> Self {
        Self {
            blockstore: Arc::new(InMemoryBlockstore::<64>::new()),
            nats_client: Arc::new(
                async_nats::connect("demo.nats.io").await.expect("should connect"),
            ),
        }
    }
}

impl BlockStore for Provider {
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

impl Resolver for Provider {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let request = DocumentRequest { url: url.to_string() };
        let document = Client::new(Store)
            .request(request)
            .owner("owner")
            .execute()
            .await
            .map(|r| r.0.clone())?;
        serde_json::to_vec(&document).map_err(|e| e.into())
    }
}

impl EventStream for Provider {
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
