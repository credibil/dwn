//! # Permissions
//!
//! Permissions are grants of authority or pre-configured access rights
//! (protocols) that can be used by authorized users to interact with a DWN.
//!
//! The [`permissions`] module brings together methods for evaluating
//! incoming messages to determine whether they have sufficient privileges to
//! undertake the message's action(s).

mod grant;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{Conditions, Grant, GrantData, Publication, RequestData, RevocationData};
use crate::protocols::{GRANT_PATH, PROTOCOL_URI, REQUEST_PATH, REVOCATION_PATH};
use crate::provider::MessageStore;
use crate::records::{RecordsFilter, Write};
use crate::store::RecordsQueryBuilder;
use crate::{Interface, Method, Result, forbidden};

/// Fetches the grant specified by `grant_id`.
pub async fn fetch_grant(owner: &str, grant_id: &str, store: &impl MessageStore) -> Result<Grant> {
    let query =
        RecordsQueryBuilder::new().add_filter(RecordsFilter::new().record_id(grant_id)).build();
    let (entries, _) = store.query(owner, &query).await?;

    let Some(entry) = entries.first() else {
        return Err(forbidden!("no grant found"));
    };
    let Some(write) = entry.as_write() else {
        return Err(forbidden!("not a valid grant"));
    };

    let desc = &write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(forbidden!("missing grant data"));
    };
    let grant_bytes = Base64UrlUnpadded::decode_vec(grant_enc)?;
    let grant: grant::GrantData = serde_json::from_slice(&grant_bytes)?;

    Ok(Grant {
        id: write.record_id.clone(),
        grantor: write.authorization.signer()?,
        grantee: desc.recipient.clone().unwrap_or_default(),
        date_granted: desc.date_created,
        data: grant,
    })
}

/// Get the scope for a permission record. If the record is a revocation, the
/// scope is fetched from the grant that is being revoked.
pub async fn fetch_scope(owner: &str, write: &Write, store: &impl MessageStore) -> Result<Scope> {
    if write.descriptor.protocol.as_deref() != Some(PROTOCOL_URI) {
        return Err(forbidden!("unexpected protocol for permission record"));
    }
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing `protocol_path`"));
    };
    let Some(encoded) = &write.encoded_data else {
        return Err(forbidden!("missing grant data"));
    };
    let raw_bytes = Base64UrlUnpadded::decode_vec(encoded)?;

    match protocol_path.as_str() {
        REQUEST_PATH => {
            let data: RequestData = serde_json::from_slice(&raw_bytes)?;
            Ok(data.scope)
        }
        GRANT_PATH => {
            let data: GrantData = serde_json::from_slice(&raw_bytes)?;
            Ok(data.scope)
        }
        REVOCATION_PATH => {
            let Some(parent_id) = &write.descriptor.parent_id else {
                return Err(forbidden!("missing parent ID for revocation record"));
            };
            let grant = fetch_grant(owner, parent_id, store).await?;
            Ok(grant.data.scope)
        }

        _ => Err(forbidden!("invalid `protocol_path`")),
    }
}

/// The `Scope` enum specifies the interface-specific scope of a permission
/// grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "interface")]
pub enum Scope {
    /// Scope applies to the `Records` interface.
    Records {
        /// The method the permission is applied to.
        method: Method,

        /// Scope protocol.
        protocol: String,

        /// Records scope options.
        #[serde(flatten)]
        #[serde(skip_serializing_if = "Option::is_none")]
        limited_to: Option<RecordsScope>,
    },

    /// Scope applies to the `Messages` interface.
    Messages {
        /// The method the permission is applied to.
        method: Method,

        /// Scope protocol.
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },

    /// Scope applies to the `Protocols` interface.
    Protocols {
        /// The method the permission is applied to.
        method: Method,

        /// Scope protocol.
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
}

impl Default for Scope {
    fn default() -> Self {
        Self::Records {
            method: Method::default(),
            protocol: String::new(),
            limited_to: None,
        }
    }
}

impl Scope {
    /// A shortcut to unpack the scope protocol.
    #[must_use]
    pub const fn interface(&self) -> Interface {
        match &self {
            Self::Records { .. } => Interface::Records,
            Self::Messages { .. } => Interface::Messages,
            Self::Protocols { .. } => Interface::Protocols,
        }
    }

    /// A shortcut to unpack the scope method.
    #[must_use]
    pub fn method(&self) -> Method {
        match self {
            Self::Records { method, .. }
            | Self::Messages { method, .. }
            | Self::Protocols { method, .. } => method.clone(),
        }
    }

    /// A shortcut to unpack the scope protocol.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        match &self {
            Self::Records { protocol, .. } => Some(protocol),
            Self::Messages { protocol, .. } | Self::Protocols { protocol, .. } => {
                protocol.as_deref()
            }
        }
    }
}

/// `RecordsScope` contains values specific to records-scoped permission
/// grants.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordsScope {
    /// The context ID of the record.
    ContextId(String),

    /// The protocol path of the record.
    ProtocolPath(String),
}

impl Default for RecordsScope {
    fn default() -> Self {
        Self::ContextId(String::new())
    }
}

impl RecordsScope {
    /// A shortcut to unpack the context ID, if it is set.
    #[must_use]
    pub fn context_id(&self) -> Option<&str> {
        match self {
            Self::ContextId(id) => Some(id.as_str()),
            Self::ProtocolPath(_) => None,
        }
    }

    /// A shortcut to access the protocol path, if it is set.
    #[must_use]
    pub fn protocol_path(&self) -> Option<&str> {
        match self {
            Self::ProtocolPath(path) => Some(path.as_str()),
            Self::ContextId(_) => None,
        }
    }
}
