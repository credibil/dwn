//! # Block Store
//!
//! Block storage support and default implementation.

pub mod data;
pub mod query;
pub mod store;

mod cid;
mod index;
mod ipfs;

use std::collections::HashMap;

use ::serde::Serialize;
use ::serde::de::DeserializeOwned;
use anyhow::Result;

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Sized + Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(
        &self, owner: &str, partition: &str, cid: &str, data: &[u8],
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(
        &self, owner: &str, partition: &str, cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(
        &self, owner: &str, partition: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The `Storable` trait is used to wrap each message with a unifying type used
/// for all stored messages (`RecordsWrite`, `RecordsDelete`, and `ProtocolsConfigure`).
#[allow(refining_impl_trait)]
pub trait Storable: Clone + Send + Sync {
    /// The message to store as a `Document`.
    ///
    /// # Errors
    ///
    /// The underlying CID computation is not infallible and may fail if the
    /// message cannot be serialized to CBOR.
    fn document(&self) -> impl Document;

    /// Indexes for this entry.
    fn indexes(&self) -> HashMap<String, String>;

    /// Adds a index item to the entry's indexes.
    fn add_index(&mut self, key: impl Into<String>, value: impl Into<String>);
}

pub trait Document: Serialize + DeserializeOwned + Send + Sync {
    /// The message's CID.
    ///
    /// # Errors
    ///
    /// The underlying CID computation is not infallible and may fail if the
    /// message cannot be serialized to CBOR.
    fn cid(&self) -> Result<String>;
}

// Custom serialization functions.
mod serde {
    use chrono::SecondsFormat::Micros;
    use chrono::{DateTime, Utc};
    use serde::Serializer;

    /// Force serializing to an RFC 3339 string with microsecond precision.
    pub fn rfc3339_micros<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339_opts(Micros, true);
        serializer.serialize_str(&s)
    }

    /// Force serializing to an RFC 3339 string with microsecond precision.
    #[allow(clippy::ref_option)]
    pub fn rfc3339_micros_opt<S>(
        date: &Option<DateTime<Utc>>, serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Some(date) = date else {
            return serializer.serialize_none();
        };
        rfc3339_micros(date, serializer)
    }
}
