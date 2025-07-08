//! # Mock WebNode

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use blockstore::{Blockstore as _, InMemoryBlockstore};
use cid::Cid;
use credibil_binding::did::Document as DidDocument;
use credibil_binding::{Binding, DocumentRequest};
use credibil_core::api::Client;
use credibil_dwn::ResumableTask;
use credibil_dwn::event::{Event, Subscriber};
use credibil_dwn::interfaces::Document;
use credibil_dwn::ipfs::Block;
use credibil_dwn::provider::{
    BlockStore, DataStore, EventLog, EventStream, MessageStore, Provider, Resolver, TaskStore,
};
use credibil_dwn::store::{Cursor, Pagination, Query, Sort, Storable};
use datastore::{data, store};
use futures::stream::StreamExt;
use ipld_core::ipld::Ipld;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::store::Datastore;

const RAW: u64 = 0x55;
const SUBJECT: &str = "events";

#[derive(Clone)]
pub struct WebNode {
    blockstore: Arc<InMemoryBlockstore<64>>,
    pub nats_client: Arc<async_nats::Client>,
}

impl WebNode {
    pub async fn new() -> Self {
        Self {
            blockstore: Arc::new(InMemoryBlockstore::<64>::new()),
            nats_client: Arc::new(
                async_nats::connect("demo.nats.io").await.expect("should connect"),
            ),
        }
    }
}

impl Provider for WebNode {}

impl Resolver for WebNode {
    async fn resolve(&self, url: &str) -> Result<Vec<u8>> {
        let request = DocumentRequest { url: url.to_string() };
        let document =
            Client::new(self.clone()).request(request).owner("owner").await.map(|r| r.0.clone())?;
        serde_json::to_vec(&document).map_err(|e| e.into())
    }
}

impl Binding for WebNode {
    async fn put(&self, owner: &str, document: &DidDocument) -> Result<()> {
        let data = serde_json::to_vec(document)?;
        Datastore::put(owner, "proof", &document.id, &data).await
    }

    async fn get(&self, owner: &str, key: &str) -> Result<Option<DidDocument>> {
        let Some(data) = Datastore::get(owner, "proof", key).await? else {
            return Err(anyhow!("could not find proof"));
        };
        Ok(serde_json::from_slice(&data)?)
    }

    async fn delete(&self, owner: &str, key: &str) -> Result<()> {
        Datastore::delete(owner, "proof", key).await
    }

    async fn get_all(&self, owner: &str) -> Result<Vec<(String, DidDocument)>> {
        Datastore::get_all(owner, "proof")
            .await?
            .iter()
            .map(|(k, v)| Ok((k.to_string(), serde_json::from_slice(v)?)))
            .collect()
    }
}

impl EventStream for WebNode {
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

impl MessageStore for WebNode {
    async fn put(&self, owner: &str, entry: &impl Storable) -> Result<()> {
        store::put(owner, "message", entry, self).await
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Document>, Option<Cursor>)> {
        store::query(owner, "message", query, self).await
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Document>> {
        store::get(owner, "message", message_cid, self).await
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        store::delete(owner, "message", message_cid, self).await
    }

    async fn purge(&self) -> Result<()> {
        todo!("implement purge")
    }
}

impl DataStore for WebNode {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, reader: impl Read + Send,
    ) -> anyhow::Result<(String, usize)> {
        let cid = safe_cid(record_id, data_cid)?;
        data::put(owner, "data", &cid, reader, self).await
    }

    async fn get(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> anyhow::Result<Option<impl Read>> {
        let cid = safe_cid(record_id, data_cid)?;
        data::get(owner, "data", &cid, self).await
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> anyhow::Result<()> {
        let cid = safe_cid(record_id, data_cid)?;
        data::delete(owner, "data", &cid, self).await
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!("implement purge")
    }
}

impl TaskStore for WebNode {
    async fn register(
        &self, _owner: &str, _task: &ResumableTask, _timeout_secs: u64,
    ) -> Result<()> {
        Ok(())
    }

    async fn grab(&self, _owner: &str, _count: u64) -> Result<Vec<ResumableTask>> {
        unimplemented!("implement grab")
    }

    async fn read(&self, _owner: &str, _task_id: &str) -> Result<Option<ResumableTask>> {
        unimplemented!("implement read")
    }

    async fn extend(&self, _owner: &str, _task_id: &str, _timeout_secs: u64) -> Result<()> {
        unimplemented!("implement extend")
    }

    async fn delete(&self, _owner: &str, _task_id: &str) -> Result<()> {
        unimplemented!("implement delete")
    }

    async fn purge(&self, _owner: &str) -> Result<()> {
        unimplemented!("implement purge")
    }
}

impl EventLog for WebNode {
    async fn append(&self, owner: &str, event: &impl Storable) -> Result<()> {
        // add a 'watermark' index entry for sorting and pagination
        let mut event = event.clone();
        event.add_index("watermark".to_string(), Ulid::new().to_string());
        store::put(owner, "eventlog", &event, self).await
    }

    async fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> Result<(Vec<Event>, Option<Cursor>)> {
        let q = Query {
            match_sets: vec![],
            pagination: Some(Pagination { limit: Some(100), cursor }),
            sort: Sort::Ascending("watermark".to_string()),
        };
        EventLog::query(self, owner, &q).await
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Event>, Option<Cursor>)> {
        store::query(owner, "eventlog", query, self).await
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        store::delete(owner, "eventlog", message_cid, self).await
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}

impl BlockStore for WebNode {
    async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        let cid = UniqueCid::new(owner, partition, key).to_cid()?;
        self.blockstore.put_keyed(&cid, block).await.map_err(Into::into)
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cid = UniqueCid::new(owner, partition, key).to_cid()?;
        let Some(bytes) = self.blockstore.get(&cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let cid = UniqueCid::new(owner, partition, key).to_cid()?;
        self.blockstore.remove(&cid).await?;
        Ok(())
    }

    async fn purge(&self, _owner: &str, _partition: &str) -> Result<()> {
        unimplemented!()
    }
}

#[derive(Serialize, Deserialize)]
struct UniqueCid<'a> {
    owner: &'a str,
    partition: &'a str,
    key: &'a str,
}

impl<'a> UniqueCid<'a> {
    fn new(owner: &'a str, partition: &'a str, key: &'a str) -> Self {
        Self { owner, partition, key }
    }

    fn to_cid(&self) -> Result<Cid> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash))
    }
}

fn safe_cid(record_id: &str, data_cid: &str) -> Result<String> {
    let block = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    Ok(block.cid().to_string())
}
