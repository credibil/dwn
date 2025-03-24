//! # Provider
//!
//! Provider traits are required of implementers in order to provide data
//! storage, DID resolution, and cryptographic capabilities to the library.

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::Result;
pub use credibil_did::{DidResolver, Document as DidDocument};
pub use datastore::BlockStore;
use datastore::{data, store};
use ipld_core::ipld::Ipld;
use ulid::Ulid;

use crate::event::{Event, Subscriber};
use crate::interfaces::Document;
use crate::store::{Cursor, Pagination, Query, Sort, Storable};
use crate::tasks::ResumableTask;

/// Provider trait.
pub trait Provider:
    MessageStore + DataStore + TaskStore + EventLog + EventStream + DidResolver
{
}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: BlockStore {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, entry: &impl Storable) -> impl Future<Output = Result<()>> + Send {
        async { store::put(owner, "MESSAGE", entry, self).await }
    }

    /// Queries the underlying store for matches to the provided query.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Document>, Option<Cursor>)>> + Send {
        async { store::query(owner, "MESSAGE", query, self).await }
    }

    /// Fetch a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = Result<Option<Document>>> + Send {
        async { store::get(owner, "MESSAGE", message_cid, self).await }
    }

    /// Delete message associated with the specified id.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async { store::delete(owner, "MESSAGE", message_cid, self).await }
    }

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async { todo!("implement purge") }
    }
}

/// The `DataStore` trait is used by implementers to provide data storage
/// capability.
pub trait DataStore: BlockStore {
    /// Store data in an underlying block store.
    ///
    /// The default implementation uses the `BlockStore` provider for storage.
    /// This may be overridden by implementers to provide custom storage.
    fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, reader: impl Read + Send,
    ) -> impl Future<Output = anyhow::Result<(String, usize)>> + Send {
        async {
            let cid = safe_cid(record_id, data_cid)?;
            data::put(owner, "DATA", &cid, reader, self).await
        }
    }

    /// Fetches a single message by CID from an underlying block store.
    fn get(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send {
        async move {
            let cid = safe_cid(record_id, data_cid)?;
            data::get(owner, "DATA", &cid, self).await
        }
    }

    /// Delete data associated with the specified id.
    fn delete(
        &self, owner: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async {
            let cid = safe_cid(record_id, data_cid)?;
            data::delete(owner, "DATA", &cid, self).await
        }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { todo!("implement purge") }
    }
}

fn safe_cid(record_id: &str, data_cid: &str) -> anyhow::Result<String> {
    let block = crate::utils::ipfs::Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    Ok(block.cid().to_string())
}

/// The `TaskStore` trait is used by implementers to provide data storage
/// capability.
pub trait TaskStore: BlockStore {
    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    fn register(
        &self, _owner: &str, _task: &ResumableTask, _timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
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
        &self, _owner: &str, _count: u64,
    ) -> impl Future<Output = Result<Vec<ResumableTask>>> + Send {
        async { unimplemented!("implement grab") }
    }

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    fn read(
        &self, _owner: &str, _task_id: &str,
    ) -> impl Future<Output = Result<Option<ResumableTask>>> + Send {
        async { unimplemented!("implement read") }
    }

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    fn extend(
        &self, _owner: &str, _task_id: &str, _timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async move { unimplemented!("implement extend") }
    }

    /// Delete data associated with the specified id.
    fn delete(&self, _owner: &str, _task_id: &str) -> impl Future<Output = Result<()>> + Send {
        async { unimplemented!("implement delete") }
    }

    /// Purge all data from the store.
    fn purge(&self, _owner: &str) -> impl Future<Output = Result<()>> + Send {
        async { unimplemented!("implement purge") }
    }
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventLog: BlockStore {
    /// Adds a message event to a owner's event log.
    fn append(
        &self, owner: &str, event: &impl Storable,
    ) -> impl Future<Output = Result<()>> + Send {
        async {
            // add a 'watermark' index entry for sorting and pagination
            let mut event = event.clone();
            event.add_index("watermark".to_string(), Ulid::new().to_string());
            store::put(owner, "EVENTLOG", &event, self).await
        }
    }

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a `message_cid`.
    fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send {
        async {
            let q = Query {
                match_sets: vec![],
                pagination: Some(Pagination {
                    limit: Some(100),
                    cursor,
                }),
                sort: Sort::Ascending("watermark".to_string()),
            };
            self.query(owner, &q).await
        }
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
        async { store::query(owner, "EVENTLOG", query, self).await }
    }

    /// Deletes event for the specified `message_cid`.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async { store::delete(owner, "EVENTLOG", message_cid, self).await }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async { todo!() }
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
