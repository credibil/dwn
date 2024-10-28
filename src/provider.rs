//! # Provider

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read;

use serde_json::Value;
pub use vercre_did::{DidResolver, Document};
pub use vercre_infosec::{Cipher, KeyOps, Signer};

use crate::messages::Sort;
use crate::query::Filter;
use crate::service::Message;
use crate::{Cursor, Pagination};

/// Issuer Provider trait.
pub trait Provider:
    MessageStore + DataStore + TaskStore + EventLog + EventStream + KeyStore + DidResolver + Clone
{
}

/// The `SecOps` trait is used to provide methods needed for signing,
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
    fn keyring(&self, controller: &str) -> anyhow::Result<impl Keyring>;

    /// Signer provides digital signing function.
    ///
    /// The `controller` parameter uniquely identifies the controller of the
    /// private key used in the signing operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be created.
    fn signer(&self, controller: &str) -> anyhow::Result<impl Signer>;

    /// Cipher provides data encryption/decryption functionality.
    ///
    /// The `controller` parameter uniquely identifies the controller of the
    /// private key used in the signing operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the encryptor cannot be created.
    fn cipher(&self, controller: &str) -> anyhow::Result<impl Cipher>;
}

/// The `SecOps` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait Keyring: Signer + Cipher + Send + Sync {}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Store a message in the underlying store.
    fn put(&self, owner: &str, message: Message)
        -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Fetches a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Message>>> + Send;

    /// Queries the underlying store for messages that matches the provided
    /// filters. Supplying multiple filters establishes an OR condition between
    /// the filters.
    fn query(
        &self, owner: &str, filters: Vec<Filter>, sort: Option<Sort>,
        pagination: Option<Pagination>,
    ) -> impl Future<Output = anyhow::Result<(Vec<Message>, Cursor)>> + Send;

    /// Delete message associated with the specified id.
    fn delete(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
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
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    fn register(
        &self, task: Value, timeout_secs: u64,
    ) -> impl Future<Output = anyhow::Result<ResumableTask>> + Send;

    /// Grabs `count` unhandled tasks from the store.
    ///
    /// Unhandled tasks are tasks that are not currently in-flight/under processing
    /// (ie. tasks that have timed-out).
    ///
    /// N.B.: The implementation must make sure that once a task is grabbed by a client,
    /// tis timeout must be updated so that it is considered in-flight/under processing
    /// and cannot be grabbed by another client until it is timed-out.
    fn grab(count: u64) -> impl Future<Output = anyhow::Result<Vec<ResumableTask>>> + Send;

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    fn read(task_id: &str) -> impl Future<Output = anyhow::Result<Option<ResumableTask>>> + Send;

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    fn extend(task_id: &str, timeout_secs: u64) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Delete data associated with the specified id.
    fn delete(&self, task_id: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
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
pub trait EventLog: Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Adds an event to a owner's event log.
    ///
    /// The `indexes` parameter is a map of key-value pairs that can be used to
    /// filter events.
    fn append(
        &self, owner: &str, message_cid: &str, indexes: BTreeMap<String, Value>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a messageCid.
    fn events(
        &self, owner: &str, cursor: Option<Cursor>,
    ) -> impl Future<Output = anyhow::Result<(Vec<String>, Cursor)>> + Send;

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    fn query(
        &self, owner: &str, filters: Vec<Filter>, cursor: Cursor,
    ) -> impl Future<Output = anyhow::Result<(Vec<String>, Cursor)>> + Send;

    /// Deletes event for the specified `message_cid`.
    fn delete(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventStream: Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Subscribes to a owner's event stream.
    fn subscribe(
        &self, owner: &str, id: &str,
        listener: impl Fn(&str, MessageEvent, BTreeMap<String, Value>),
    ) -> impl Future<Output = anyhow::Result<(String, impl EventSubscription)>> + Send;

    /// Emits an event to a owner's event stream.
    fn emit(
        &self, owner: &str, event: MessageEvent, indexes: BTreeMap<String, Value>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// `EventSubscription` is a subscription to an event stream.
pub trait EventSubscription {
    /// Close the subscription to the event stream.
    fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// `MessageEvent` contains the message being emitted and an optional initial
/// write message.
pub struct MessageEvent {
    /// The message being emitted.
    pub message: Message,

    /// The initial write of the `RecordsWrite` or `RecordsDelete` message.
    pub initial_write: Option<Message>,
    // pub initial_write: Option<RecordsWriteMessage>
}
