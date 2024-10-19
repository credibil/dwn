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

use serde::Deserialize;
use serde_json::Value;
use surrealdb::engine::local::{Db, Mem};
use surrealdb::opt::RecordId;
use surrealdb::Surreal;
use vercre_dwn::protocols::Configure;
use vercre_dwn::provider::{DidResolver, EventStream, EventSubscription, MessageEvent, Provider};

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    pub async fn new() -> anyhow::Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns("testing").use_db("tenant").await?;

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
    async fn resolve(&self, url: &str) -> anyhow::Result<String> {
        todo!()
    }
}

struct EventSubscriptionImpl;

impl EventSubscription for EventSubscriptionImpl {
    async fn close(&self) -> anyhow::Result<()> {
        todo!()
    }
}

impl EventStream for ProviderImpl {
    /// Subscribes to a tenant's event stream.
    fn subscribe(
        &self, tenant: &str, id: &str,
        listener: impl Fn(&str, MessageEvent, BTreeMap<String, Value>),
    ) -> impl Future<Output = anyhow::Result<(String, impl EventSubscription)>> + Send {
        async { Ok((String::new(), EventSubscriptionImpl {})) }
    }

    //: Promise<EventSubscription>;

    /// Emits an event to a tenant's event stream.
    async fn emit(
        &self, tenant: &str, event: MessageEvent, indexes: BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        todo!()
    }
}
