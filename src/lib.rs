//! # Decentralized Web Node (DWN)
//!
//! A [Decentralized Web Node (DWN)] is a data storage and message relay
//! mechanism entities can use to locate public or private permissioned data
//! related to a given Decentralized Identifier (DID). Decentralized Web Nodes
//! are designed to be deployed in mesh-like datastore construct that enables
//! an entity to operate multiple nodes that replicate state across all nodes.
//!
//! A DWN allows the owning entity to secure, manage, and transact data with
//! others without reliance on location or provider-specific infrastructure,
//! interfaces, or routing mechanisms.
//!
//! [Decentralized Web Node (DWN)]: https://identity.foundation/working-groups/didcomm-messaging/spec/#decentralized-web-node-dwn

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod authorization;
mod error;
pub mod event;
mod grants;
pub mod hd_key;
pub mod interfaces;
mod utils;

#[cfg(feature = "client")]
pub mod client;

cfg_if::cfg_if! {
    if #[cfg(feature = "server")] {
        pub mod endpoint;
        mod handlers;
        pub mod provider;
        mod schema;
        pub mod store;
        mod tasks;

        // re-exports
        pub use http::StatusCode;

        pub use crate::endpoint::Message;
        pub use crate::provider::Provider;
        pub use crate::utils::cid;
    }
}

// Re-exports
use ::serde::{Deserialize, Serialize};
pub use credibil_infosec::{Receiver, Signer};
use derive_more::Display;

pub use crate::error::Error;

/// Result type for `DWN` handlers.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Send + Sync {
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

/// Web node interfaces.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
pub enum Interface {
    /// Records interface.
    #[default]
    Records,

    /// Protocols interface.
    Protocols,

    /// Messages interface.
    Messages,
}

/// Interface methods.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
pub enum Method {
    /// Read method.
    #[default]
    Read,
    /// Write method.
    Write,
    /// Query method.
    Query,
    /// Configure method.
    Configure,
    /// Subscribe method.
    Subscribe,
    /// Delete method.
    Delete,
}

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Protocol {
    /// HTTP protocol.
    #[default]
    Http,
}

/// `OneOrMany` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single object.
    One(T),
    /// A set of objects.
    Many(Vec<T>),
}

impl<T: Default> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T: Clone> OneOrMany<T> {
    /// Convert the quota to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Many(value)
    }
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
