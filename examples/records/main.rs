#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read;

use serde::Deserialize;
use serde_json::Value;
use surrealdb::engine::local::{Db, Mem};
use surrealdb::opt::RecordId;
use surrealdb::Surreal;
use vercre_dwn::messages::{Filter, Sort};
use vercre_dwn::provider::{
    DataStore, DidResolver, EventLog, EventStream, EventSubscription, MessageEvent, MessageStore,
    Provider, ResumableTask, TaskStore,
};
use vercre_dwn::service::Message;
use vercre_dwn::{messages, Cursor, Pagination};

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let msg = Message::MessagesQuery(messages::Query::default());
    let _ = vercre_dwn::send_message(msg, provider).await;
}

#[derive(Clone)]
struct ProviderImpl {
    db: Surreal<Db>,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    async fn new() -> anyhow::Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns("testing").use_db("test").await?;

        Ok(Self { db })
    }
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> anyhow::Result<String> {
        todo!()
    }
}

#[derive(Debug, Deserialize)]
struct Record {
    #[allow(dead_code)]
    id: RecordId,
}

impl MessageStore for ProviderImpl {
    async fn put(
        &self, tenant: &str, message: Message, _indexes: BTreeMap<&str, &str>,
    ) -> anyhow::Result<()> {
        self.db.use_ns("testing").use_db(tenant).await?;
        let _: Option<Message> =
            self.db.create(("message", message.cid()?)).content(message).await?;
        Ok(())
    }

    async fn get(&self, tenant: &str, cid: &str) -> anyhow::Result<Option<Message>> {
        self.db.use_ns("testing").use_db(tenant).await?;
        Ok(self.db.select(("message", cid)).await?)
    }

    async fn query(
        &self, tenant: &str, filters: Vec<Filter>, sort: Option<Sort>,
        pagination: Option<Pagination>,
    ) -> anyhow::Result<(Vec<Message>, Cursor)> {
        self.db.use_ns("testing").use_db(tenant).await?;

        let mut response =
            self.db.query("SELECT * FROM type::table($table)").bind(("table", "message")).await?;

        let messages: Vec<Message> = response.take(0)?;

        // Ok(response.take(0)?)
        Ok((messages, Cursor::default()))
    }

    async fn delete(&self, tenant: &str, cid: &str) -> anyhow::Result<()> {
        self.db.use_ns("testing").use_db(tenant).await?;
        let person: Option<Message> = self.db.delete(("message", cid)).await?;
        Ok(())
    }

    async fn purge(&self) -> anyhow::Result<()> {
        self.db.use_ns("testing");

        Ok(())
    }
}

impl DataStore for ProviderImpl {
    fn put(
        &self, tenant: &str, record_id: &str, data_cid: &str, data: impl Read,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }

    fn get(
        &self, tenant: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send {
        let buf = vec![];
        let reader = std::io::Cursor::new(buf);
        async { Ok(Some(reader)) }
    }

    async fn delete(&self, tenant: &str, record_id: &str, data_cid: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!()
    }
}

impl TaskStore for ProviderImpl {
    async fn register(&self, task: Value, timeout_secs: u64) -> anyhow::Result<ResumableTask> {
        todo!()
    }

    async fn grab(count: u64) -> anyhow::Result<Vec<ResumableTask>> {
        todo!()
    }

    async fn read(task_id: &str) -> anyhow::Result<Option<ResumableTask>> {
        todo!()
    }

    async fn extend(task_id: &str, timeout_secs: u64) -> anyhow::Result<()> {
        todo!()
    }

    async fn delete(&self, task_id: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl EventLog for ProviderImpl {
    async fn append(
        &self, tenant: &str, message_cid: &str, indexes: BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        todo!()
    }

    async fn events(tenant: &str, cursor: Option<Cursor>) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn query_events(
        tenant: &str, filters: Vec<Filter>, cursor: Cursor,
    ) -> anyhow::Result<(Vec<String>, Cursor)> {
        todo!()
    }

    async fn delete_events(tenant: &str, message_cids: Vec<&str>) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
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
