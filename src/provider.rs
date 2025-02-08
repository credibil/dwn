//! # Provider
//!
//! Provider traits are required of implementers in order to provide data
//! storage, DID resolution, and cryptographic capabilities to the library.

use std::io::Read;

use anyhow::Result;
pub use credibil_did::{DidResolver, Document};

use crate::event::{Event, Subscriber};
use crate::interfaces::Cursor;
use crate::store::{Entry, Query, data, event_log, message, task};
use crate::tasks::ResumableTask;

/// Provider trait.
pub trait Provider:
    MessageStore + DataStore + TaskStore + EventLog + BlockStore + EventStream + DidResolver
{
}

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(
        &self, owner: &str, partition: &str, cid: &str, data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(&self, owner: &str, partition: &str) -> impl Future<Output = Result<()>> + Send;
}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: BlockStore + Sized + Send + Sync {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, entry: &Entry) -> impl Future<Output = Result<()>> + Send {
        async move { message::put(owner, entry, self).await.map_err(Into::into) }
    }

    /// Queries the underlying store for matches to the provided query.
    // fn query(&self, owner: &str, query: &Query) -> impl Future<Output = Result<Vec<Entry>>> + Send;
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Entry>, Option<Cursor>)>> + Send {
        async move { message::query(owner, query, self).await.map_err(Into::into) }
    }

    /// Fetch a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = Result<Option<Entry>>> + Send {
        async move { message::get(owner, message_cid, self).await.map_err(Into::into) }
    }

    /// Delete message associated with the specified id.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async move { message::delete(owner, message_cid, self).await.map_err(Into::into) }
    }

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async move { todo!("implement purge") }
    }
}

/// The `DataStore` trait is used by implementers to provide data storage
/// capability.
pub trait DataStore: BlockStore + Sized + Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Store data in an underlying block store.
    ///
    /// The default implementation uses the `BlockStore` provider for storage.
    /// This may be overridden by implementers to provide custom storage.
    fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, reader: impl Read + Send,
    ) -> impl Future<Output = anyhow::Result<(String, usize)>> + Send {
        async move { data::put(owner, record_id, data_cid, reader, self).await.map_err(Into::into) }
    }

    /// Fetches a single message by CID from an underlying block store.
    fn get(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send {
        async move { data::get(owner, record_id, data_cid, self).await.map_err(Into::into) }
    }

    /// Delete data associated with the specified id.
    fn delete(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async move { data::delete(owner, record_id, data_cid, self).await.map_err(Into::into) }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send {
        async move { todo!("implement purge") }
    }
}

/// The `TaskStore` trait is used by implementers to provide data storage
/// capability.
pub trait TaskStore: BlockStore + Sized + Send + Sync {
    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    fn register(
        &self, owner: &str, task: &ResumableTask, timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async move { task::register(owner, task, timeout_secs, self).await.map_err(Into::into) }
    }

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
    ) -> impl Future<Output = Result<Vec<ResumableTask>>> + Send {
        async move { task::grab(owner, count, self).await.map_err(Into::into) }
    }

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    fn read(
        &self, owner: &str, task_id: &str,
    ) -> impl Future<Output = Result<Option<ResumableTask>>> + Send {
        async move { task::read(owner, task_id, self).await.map_err(Into::into) }
    }

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    fn extend(
        &self, owner: &str, task_id: &str, timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async move { task::extend(owner, task_id, timeout_secs, self).await.map_err(Into::into) }
    }

    /// Delete data associated with the specified id.
    fn delete(&self, owner: &str, task_id: &str) -> impl Future<Output = Result<()>> + Send {
        async move { task::delete(owner, task_id, self).await.map_err(Into::into) }
    }

    /// Purge all data from the store.
    fn purge(&self, _owner: &str) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventLog: BlockStore + Sized + Send + Sync {
    /// Adds a message event to a owner's event log.
    fn append(&self, owner: &str, event: &Entry) -> impl Future<Output = Result<()>> + Send {
        async move { event_log::append(owner, event, self).await.map_err(Into::into) }
    }

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a `message_cid`.
    fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send {
        async move { event_log::events(owner, cursor, self).await.map_err(Into::into) }
    }

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send {
        async move { event_log::query(owner, query, self).await.map_err(Into::into) }
    }

    /// Deletes event for the specified `message_cid`.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async move { event_log::delete(owner, message_cid, self).await.map_err(Into::into) }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }
}

/// The `EventStream` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventStream: Send + Sync {
    /// Subscribes to an owner's event stream.
    fn subscribe(&self, owner: &str) -> impl Future<Output = Result<Subscriber>> + Send;

    /// Emits an event to a owner's event stream.
    fn emit(&self, owner: &str, event: &Event) -> impl Future<Output = Result<()>> + Send;
}
