//! # Provider

use std::io::Read;

use anyhow::Result;
pub use vercre_did::{DidResolver, Document};
pub use vercre_infosec::{Receiver, Signer};

use crate::event::{Event, Subscriber};
use crate::store::Cursor;
pub use crate::store::{Entry, Query};
pub use crate::tasks::ResumableTask;

/// Provider trait.
pub trait Provider:
    MessageStore + BlockStore + TaskStore + EventLog + EventStream + DidResolver
{
}

/// The `BlockStore` trait is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(&self, owner: &str, cid: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(&self, owner: &str, cid: &str) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(&self, owner: &str, cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: Send + Sync {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, record: &Entry) -> impl Future<Output = Result<()>> + Send;

    /// Queries the underlying store for matches to the provided query.
    // fn query(&self, owner: &str, query: &Query) -> impl Future<Output = Result<Vec<Entry>>> + Send;
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Entry>, Option<Cursor>)>> + Send;

    /// Fetches a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = Result<Option<Entry>>> + Send;

    /// Delete message associated with the specified id.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The `DataStore` trait is used by implementers to provide data storage
/// capability.
pub trait DataStore: Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Store data in the underlying store.
    fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, data: impl Read,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Fetches a single message by CID from the underlying store, returning
    /// `None` if no match was found.
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
    fn append(&self, owner: &str, event: &Event) -> impl Future<Output = Result<()>> + Send;

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
