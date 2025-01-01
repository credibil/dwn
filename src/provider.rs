//! # Provider

use anyhow::{Result, anyhow};
pub use vercre_did::{DidResolver, Document};
pub use vercre_infosec::{KeyOps, Receiver, Signer};

use crate::event::{Event, Subscriber};
use crate::store::Cursor;
pub use crate::store::{Entry, Query};
pub use crate::tasks::ResumableTask;

/// Issuer Provider trait.
pub trait Provider:
    MessageStore + BlockStore + TaskStore + EventLog + EventStream + KeyStore + DidResolver
{
}

/// The `KeyStore` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait KeyStore: Send + Sync {
    /// Signer provides digital signing function.
    ///
    /// The `controller` parameter uniquely identifies the controller of the
    /// private key used in the signing operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be created.
    fn keyring(&self, controller: &str) -> Result<impl Keyring>;

    // /// Signer provides digital signing function.
    // ///
    // /// The `controller` parameter uniquely identifies the controller of the
    // /// private key used in the signing operation.
    // ///
    // /// # Errors
    // ///
    // /// Returns an error if the signer cannot be created.
    // fn signer(&self, controller: &str) -> impl Future<Output = Result<impl Signer>>+Send;

    // /// Cipher provides data encryption/decryption functionality.
    // ///
    // /// The `controller` parameter uniquely identifies the controller of the
    // /// private key used in the signing operation.
    // ///
    // /// # Errors
    // ///
    // /// Returns an error if the encryptor cannot be created.
    // fn cipher(&self, controller: &str) -> impl Future<Output = Result<impl Cipher>>+Send;
}

/// The `Keyring` trait provides the methods needed for signing, encrypting,
/// verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait Keyring: Signer + Receiver {}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: Send + Sync {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, record: &Entry) -> impl Future<Output = Result<()>> + Send;

    /// Queries the underlying store for matches to the provided query.
    fn query(&self, owner: &str, query: &Query) -> impl Future<Output = Result<Vec<Entry>>> + Send;

    /// Queries the underlying store returning the current page of results.
    fn paginated_query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Entry>, Option<Cursor>)>> + Send {
        async move {
            let entries = self.query(owner, query).await?;

            // no pagination
            let Query::Records(query) = query else {
                return Ok((entries, None));
            };
            // no pagination
            let Some(pagination) = &query.pagination else {
                return Ok((entries, None));
            };
            // sorted on?
            let Some(sort_field) = &query.sort else {
                return Ok((entries, None));
            };
            // additional results?
            let mut limit = pagination.limit.unwrap_or(entries.len());
            if entries.len() <= limit {
                return Ok((entries, None));
            }

            // page offset
            let offset = if let Some(cursor) = &pagination.cursor {
                // find starting point
                let Some(index) =
                    entries.iter().position(|e| e.cid().ok().as_ref() == Some(&cursor.message_cid))
                else {
                    return Err(anyhow!("cursor `message_cid` is invalid"));
                };
                index
            } else {
                0
            };

            // don't blow upper bound
            if offset + limit > entries.len() {
                limit = entries.len() - offset;
            }

            // capture page
            let curr_page = entries.as_slice()[offset..offset + limit].to_vec();

            // starting point for the next page (using `message_cid`)
            let Some(next_entry) = entries.get(offset + limit) else {
                return Ok((curr_page, None));
            };

            Ok((
                curr_page,
                Some(Cursor {
                    message_cid: next_entry.cid()?,
                    sort_value: sort_field.to_string(),
                }),
            ))
        }
    }

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

/// The `BlockStore` trait is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(&self, owner: &str, cid: &str, block: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(&self, owner: &str, cid: &str) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(&self, owner: &str, cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
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
    ) -> impl Future<Output = Result<(Vec<Event>, Cursor)>> + Send;

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Event>, Cursor)>> + Send;

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
