//! # Provider
//!
//! The Provider trait and its associated super traits are implemented by
//! library users to provide data storage, DID resolution, and cryptographic
//! capabilities to the library. The library is designed to be extensible and
//! modular, allowing users to implement their own providers for different
//! storage backends, DID resolution mechanisms, and cryptographic algorithms.
//! implementers in order to provide data storage, DID resolution, and
//! cryptographic capabilities to the library.
//!
//! To implement storage-related traits library users need only implement the
//! `BlockStore` trait, which is used to store and retrieve data. Users can
//! implement the other traits as needed.

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::Result;
pub use credibil_binding::Resolver;
pub use datastore::BlockStore;
use datastore::{data, store};
use ipld_core::ipld::Ipld;
use ulid::Ulid;

use crate::event::{Event, Subscriber};
use crate::interfaces::Document;
use crate::store::{Cursor, Pagination, Query, Sort, Storable};
use crate::tasks::ResumableTask;
use crate::utils::ipfs::Block;

/// Provider trait.
pub trait Provider:
    MessageStore + DataStore + TaskStore + EventLog + EventStream + Resolver
{
}

/// A blanket implementation for `Provider` trait  to allow any type
/// implementing the required super traits to be considered a `Provider`.
impl<T> Provider for T where
    T: MessageStore + DataStore + TaskStore + EventLog + EventStream + Resolver
{
}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: Send + Sync {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, entry: &impl Storable) -> impl Future<Output = Result<()>> + Send;

    /// Queries the underlying store for matches to the provided query.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Document>, Option<Cursor>)>> + Send;

    /// Fetch a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = Result<Option<Document>>> + Send;

    /// Delete message associated with the specified id.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The `DataStore` trait is used by implementers to provide data storage
/// capability.
pub trait DataStore: Send + Sync {
    /// Store data in an underlying block store.
    ///
    /// The default implementation uses the `BlockStore` provider for storage.
    /// This may be overridden by implementers to provide custom storage.
    fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, reader: impl Read + Send,
    ) -> impl Future<Output = anyhow::Result<(String, usize)>> + Send;

    /// Fetches a single message by CID from an underlying block store.
    fn get(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send;

    /// Delete data associated with the specified id.
    fn delete(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The `TaskStore` trait is used by implementers to provide data storage
/// capability.
pub trait TaskStore: Send + Sync {
    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    fn register(
        &self, owner: &str, task: &ResumableTask, timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Grabs `count` unhandled tasks from the store.
    ///
    /// Unhandled tasks are tasks that are not currently in-flight/under processing
    /// (ie. tasks that have timed-out).
    ///
    /// N.B.: The implementation must make sure that once a task is grabbed by a client,
    /// tis timeout must be updated so that it is considered in-flight/under processing
    /// and cannot be grabbed by another client until it is timed-out.
    fn grab(
        &self, owner: &str, count: u64,
    ) -> impl Future<Output = Result<Vec<ResumableTask>>> + Send;

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    fn read(
        &self, owner: &str, task_id: &str,
    ) -> impl Future<Output = Result<Option<ResumableTask>>> + Send;

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    fn extend(
        &self, owner: &str, task_id: &str, timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Delete data associated with the specified id.
    fn delete(&self, owner: &str, task_id: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all data from the store.
    fn purge(&self, owner: &str) -> impl Future<Output = Result<()>> + Send;
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventLog: Send + Sync {
    /// Adds a message event to a owner's event log.
    fn append(&self, owner: &str, event: &impl Storable)
    -> impl Future<Output = Result<()>> + Send;

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a `message_cid`.
    fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send;

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send;

    /// Deletes event for the specified `message_cid`.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The `EventStream` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventStream: Send + Sync {
    /// Subscribes to an owner's event stream.
    fn subscribe(&self, owner: &str) -> impl Future<Output = Result<Subscriber>> + Send;

    /// Emits an event to a owner's event stream.
    fn emit(&self, owner: &str, event: &Event) -> impl Future<Output = Result<()>> + Send;
}

impl<T: BlockStore> MessageStore for T {
    async fn put(&self, owner: &str, entry: &impl Storable) -> Result<()> {
        store::put(owner, "MESSAGE", entry, self).await
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Document>, Option<Cursor>)> {
        store::query(owner, "MESSAGE", query, self).await
    }

    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<Document>> {
        store::get(owner, "MESSAGE", message_cid, self).await
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        store::delete(owner, "MESSAGE", message_cid, self).await
    }

    async fn purge(&self) -> Result<()> {
        todo!("implement purge")
    }
}

impl<T: BlockStore> DataStore for T {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, reader: impl Read + Send,
    ) -> anyhow::Result<(String, usize)> {
        let cid = safe_cid(record_id, data_cid)?;
        data::put(owner, "DATA", &cid, reader, self).await
    }

    async fn get(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> anyhow::Result<Option<impl Read>> {
        let cid = safe_cid(record_id, data_cid)?;
        data::get(owner, "DATA", &cid, self).await
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> anyhow::Result<()> {
        let cid = safe_cid(record_id, data_cid)?;
        data::delete(owner, "DATA", &cid, self).await
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!("implement purge")
    }
}

impl<T: BlockStore> TaskStore for T {
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

impl<T> EventLog for T
where
    T: BlockStore,
{
    async fn append(&self, owner: &str, event: &impl Storable) -> Result<()> {
        // add a 'watermark' index entry for sorting and pagination
        let mut event = event.clone();
        event.add_index("watermark".to_string(), Ulid::new().to_string());
        store::put(owner, "EVENTLOG", &event, self).await
    }

    async fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> Result<(Vec<Event>, Option<Cursor>)> {
        let q = Query {
            match_sets: vec![],
            pagination: Some(Pagination {
                limit: Some(100),
                cursor,
            }),
            sort: Sort::Ascending("watermark".to_string()),
        };
        EventLog::query(self, owner, &q).await
    }

    async fn query(&self, owner: &str, query: &Query) -> Result<(Vec<Event>, Option<Cursor>)> {
        store::query(owner, "EVENTLOG", query, self).await
    }

    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()> {
        store::delete(owner, "EVENTLOG", message_cid, self).await
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}

fn safe_cid(record_id: &str, data_cid: &str) -> anyhow::Result<String> {
    let block = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    Ok(block.cid().to_string())
}
