//! # Store
//!
//! The `store` module provides utilities for storing and retrieving messages
//! and associated data.
//!
//! The two primary types exposed by this module are [`Storable`] and [`Query`].
//!
//! [`Storable`] wraps each message with a unifying type used to simplify storage
//! and retrieval as well as providing a vehicle for attaching addtional data
//! alongside the message (i.e. indexes).
//!
//! [`Query`] wraps store-specific query options for querying the underlying
//! store.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;

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
