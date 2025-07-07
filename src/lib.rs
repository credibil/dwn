//! # Decentralized Web Node (DWN)
//!
//! A [Decentralized Web Node (DWN)] is a data storage and message relay
//! mechanism that can be used to share public or private permissioned data
//! for a given Decentralized Identifier (DID).
//!
//! DWNs are designed to be deployed in mesh-like datastore construct that
//! replicates state across all nodes. The owner can secure, manage, and
//! transact data with others without reliance on location or provider-specific
//! infrastructure, interfaces, or routing mechanisms.
//!
//! [Decentralized Web Node (DWN)]: https://identity.foundation/working-groups/didcomm-messaging/spec/#decentralized-web-node-dwn

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod authorization;
pub mod event;
pub mod hd_key;
pub mod interfaces;

mod error;
mod grants;
mod utils;

pub use credibil_ecc::{Receiver, Signer};

pub use self::utils::*;

#[cfg(feature = "client")]
pub mod client;

cfg_if::cfg_if! {
    if #[cfg(feature = "server")] {
        pub mod provider;
        pub mod store;

        mod handlers;
        mod schema;
        mod tasks;

        pub use ::http::StatusCode;
        pub use credibil_core::{http, api};

        pub use self::tasks::*;
        pub use self::provider::Provider;
        pub use self::utils::cid;
    }
}

use ::serde::{Deserialize, Serialize};
use derive_more::Display;

pub use self::handlers::*;

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
