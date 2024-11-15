//! # Provider

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
pub use vercre_did::{DidResolver, Document};
pub use vercre_infosec::{Cipher, KeyOps, Signer};

use crate::endpoint::MessageRecord;
use crate::event::{Event, Listener, Subscriber};
use crate::Cursor;

/// Issuer Provider trait.
pub trait Provider:
    MessageStore + BlockStore + TaskStore + EventLog + EventStream + KeyStore + DidResolver + Clone
{
}

/// The `KeyStore` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.

#[async_trait]
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
    // fn signer(&self, controller: &str) -> Result<impl Signer>;

    // /// Cipher provides data encryption/decryption functionality.
    // ///
    // /// The `controller` parameter uniquely identifies the controller of the
    // /// private key used in the signing operation.
    // ///
    // /// # Errors
    // ///
    // /// Returns an error if the encryptor cannot be created.
    // fn cipher(&self, controller: &str) -> Result<impl Cipher>;
}

/// The `Keyring` trait provides the methods needed for signing, encrypting,
/// verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
#[async_trait]
pub trait Keyring: Signer + Cipher + Send + Sync {}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Store a message in the underlying store.
    async fn put(&self, owner: &str, record: &MessageRecord) -> Result<()>;

    /// Queries the underlying store for matches to the provided SQL WHERE clause.
    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<MessageRecord>, Cursor)>;

    /// Fetches a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    async fn get(&self, owner: &str, message_cid: &str) -> Result<Option<MessageRecord>>;

    /// Delete message associated with the specified id.
    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()>;

    /// Purge all records from the store.
    async fn purge(&self) -> Result<()>;
}

/// The `BlockStore` trait is used by implementers to provide data storage
/// capability.
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Store a data block in the underlying block store.
    async fn put(&self, owner: &str, cid: &str, block: &[u8]) -> Result<()>;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    async fn get(&self, owner: &str, cid: &str) -> Result<Option<Vec<u8>>>;

    /// Delete the data block associated with the specified CID.
    async fn delete(&self, owner: &str, cid: &str) -> Result<()>;

    /// Purge all blocks from the store.
    async fn purge(&self) -> Result<()>;
}

/// The `TaskStore` trait is used by implementers to provide data storage
/// capability.
#[async_trait]
pub trait TaskStore: Send + Sync {
    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    async fn register(&self, task: &Value, timeout_secs: u64) -> Result<ResumableTask>;

    /// Grabs `count` unhandled tasks from the store.
    ///
    /// Unhandled tasks are tasks that are not currently in-flight/under processing
    /// (ie. tasks that have timed-out).
    ///
    /// N.B.: The implementation must make sure that once a task is grabbed by a client,
    /// tis timeout must be updated so that it is considered in-flight/under processing
    /// and cannot be grabbed by another client until it is timed-out.
    async fn grab(count: u64) -> Result<Vec<ResumableTask>>;

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    async fn read(task_id: &str) -> Result<Option<ResumableTask>>;

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    async fn extend(task_id: &str, timeout_secs: u64) -> Result<()>;

    /// Delete data associated with the specified id.
    async fn delete(&self, task_id: &str) -> Result<()>;

    /// Purge all data from the store.
    async fn purge(&self) -> Result<()>;
}

/// An managed resumable task model.
pub struct ResumableTask {
    /// Globally unique ID. Used to extend or delete the task.
    pub id: String,

    /// Task specific data. This is deliberately of type `any` because this store
    /// should not have to be ware of its type.
    pub task: Value,

    /// Task timeout in Epoch Time.
    pub timeout: u64,

    /// Number of retries
    pub retry_count: u64,
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
#[async_trait]
pub trait EventLog: Send + Sync {
    /// Adds a message event to a owner's event log.
    async fn append(&self, owner: &str, event: &Event) -> Result<()>;

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a `message_cid`.
    async fn events(&self, owner: &str, cursor: Option<Cursor>) -> Result<(Vec<Event>, Cursor)>;

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    async fn query(&self, owner: &str, sql: &str) -> Result<(Vec<Event>, Cursor)>;

    /// Deletes event for the specified `message_cid`.
    async fn delete(&self, owner: &str, message_cid: &str) -> Result<()>;

    /// Purge all data from the store.
    async fn purge(&self) -> Result<()>;
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
#[async_trait]
pub trait EventStream: Send + Sync {
    /// Subscribes to a owner's event stream.
    async fn subscribe(
        &self, owner: &str, message_cid: &str, listener: &Listener,
    ) -> Result<Subscriber>;

    /// Emits an event to a owner's event stream.
    async fn emit(&self, owner: &str, event: &Event) -> Result<()>;
}

/// `EventSubscription` is a subscription to an event stream.
#[async_trait]
pub trait EventSubscription: Send + Sync {
    /// Close the subscription to the event stream.
    async fn close(&self) -> Result<()>;
}
