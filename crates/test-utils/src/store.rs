#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod data;
pub mod event;
pub mod message;
pub mod task;

use std::collections::BTreeMap;
use std::future::Future;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::Value;
use surrealdb::engine::local::{Db, Mem};
use surrealdb::opt::RecordId;
use surrealdb::Surreal;
use vercre_dwn::protocols::Configure;
use vercre_dwn::provider::{
    DidResolver, Document, EventStream, EventSubscription, MessageEvent, Provider,
};

use crate::signer::OWNER_DID;

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns("testing").use_db(OWNER_DID).await?;

        let bytes = include_bytes!("./store/protocol.json");
        let config: Configure = serde_json::from_slice(bytes).expect("should deserialize");
        let _: Vec<Record> = db.create("protocol").content(config).await.expect("should create");

        Ok(Self { db })
    }
}

#[derive(Debug, Deserialize)]
struct Record {
    #[allow(dead_code)]
    id: RecordId,
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        serde_json::from_slice(include_bytes!("./store/did.json"))
            .map_err(|e| anyhow!("issue deserializing document: {e}"))
    }
}

struct EventSubscriptionImpl;

impl EventSubscription for EventSubscriptionImpl {
    async fn close(&self) -> Result<()> {
        todo!()
    }
}

impl EventStream for ProviderImpl {
    /// Subscribes to a owner's event stream.
    fn subscribe(
        &self, owner: &str, id: &str,
        listener: impl Fn(&str, MessageEvent, BTreeMap<String, Value>),
    ) -> impl Future<Output = Result<(String, impl EventSubscription)>> + Send {
        async { Ok((String::new(), EventSubscriptionImpl {})) }
    }

    //: Promise<EventSubscription>;

    /// Emits an event to a owner's event stream.
    async fn emit(
        &self, owner: &str, event: MessageEvent, indexes: BTreeMap<String, Value>,
    ) -> Result<()> {
        todo!()
    }
}
