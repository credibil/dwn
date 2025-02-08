//! # Permissions
//!
//! Permissions are grants of authority or pre-configured access rights
//! (protocols) that can be used by authorized users to interact with a DWN.
//!
//! The [`permissions`] module brings together methods for evaluating
//! incoming messages to determine whether they have sufficient privileges to
//! undertake the message's action(s).

mod verify;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::interfaces::protocols::{GRANT_PATH, PROTOCOL_URI, REQUEST_PATH, REVOCATION_PATH};
use crate::interfaces::records::{DelegatedGrant, RecordsFilter, Write};
use crate::provider::MessageStore;
use crate::serde::rfc3339_micros;
use crate::store::RecordsQueryBuilder;
use crate::{Interface, Method, Result, forbidden, unexpected};

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
    let grant: GrantData = serde_json::from_slice(&grant_bytes)?;

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

/// [`Grant`] holds permission grant information during the process of
/// verifying an incoming message's authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    /// The ID of the permission grant — the record ID message.
    pub id: String,

    /// The grantor of the permission.
    pub grantor: String,

    /// The grantee of the permission.
    pub grantee: String,

    /// The date at which the grant was given.
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_granted: DateTime<Utc>,

    /// The grant's descriptor.
    #[serde(flatten)]
    pub data: GrantData,
}

impl TryFrom<&Write> for Grant {
    type Error = crate::Error;

    fn try_from(write: &Write) -> Result<Self> {
        let permission_grant = write.encoded_data.clone().unwrap_or_default();
        let grant_data = serde_json::from_str(&permission_grant)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        Ok(Self {
            id: write.record_id.clone(),
            grantor: write.authorization.signer().unwrap_or_default(),
            grantee: write.descriptor.recipient.clone().unwrap_or_default(),
            date_granted: write.descriptor.date_created,
            data: grant_data,
        })
    }
}

impl TryFrom<&DelegatedGrant> for Grant {
    type Error = crate::Error;

    fn try_from(delegated: &DelegatedGrant) -> Result<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(&delegated.encoded_data)?;
        let grant_data = serde_json::from_slice(&bytes)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        Ok(Self {
            id: delegated.record_id.clone(),
            grantor: delegated.authorization.signer()?,
            grantee: delegated.descriptor.recipient.clone().unwrap_or_default(),
            date_granted: delegated.descriptor.date_created,
            data: grant_data,
        })
    }
}

/// The [`GrantData`] data structure holds information related to a permission
/// grant.
///
/// The grant is issued as a [`Write`] message with the base64 URL-encoded
/// [`GrantData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantData {
    /// Describes the intended grant use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The CID of permission request. This is optional as grants may be issued
    /// without being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// The date-time when grant expires.
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_expires: DateTime<Utc>,

    /// Specifies whether grant is delegated or not. When set to `true`, the
    /// `granted_to` property acts as the `granted_to` within the scope of the
    /// grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,

    /// The scope of access permitted by the grant.
    pub scope: Scope,

    /// Specifies an conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// [`Conditions`] contains conditions set on the parent `Grant`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conditions {
    /// Indicates whether a message written with the invocation of a permission
    /// must, may, or must not be marked as public. If unset, it is optional to
    /// make the message public.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication: Option<Publication>,
}

/// Condition for publication of a message.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Publication {
    /// The message must be marked as public.
    #[default]
    Required,

    /// The message may be marked as public.
    Prohibited,
}

/// The [`RequestData`] data structure holds information related to a permission
/// grant request.
///
/// The request is made using a [`Write`] message with the base64 URL-encoded
/// [`RequestData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RequestData {
    /// If the grant is a delegated grant or not. If `true`, `granted_to` will
    /// be able to act as the `granted_by` within the scope of this grant.
    pub delegated: bool,

    /// Optional string that communicates what the grant would be used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// The [`RevocationData`] data structure holds information related to a permission
/// grant revocation.
///
/// The revocation is saved as a [`Write`] message with the base64 URL-encoded
/// [`RevocationData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationData {
    /// Optional string that communicates the details of the revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
