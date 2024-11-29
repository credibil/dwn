//! # Permissions

mod grant;
mod protocol;
mod request;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{Grant, GrantBuilder, GrantData, RequestData, RevocationData};
pub(crate) use self::protocol::{Protocol, fetch_scope};
use crate::provider::MessageStore;
use crate::records::Write;
use crate::store::RecordsQuery;
use crate::{Interface, Method, Result, unexpected};

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    owner: &str, grant_id: &str, store: &impl MessageStore,
) -> Result<Grant> {
    let query = RecordsQuery::new().record_id(grant_id).build();
    let (records, _) = store.query(owner, &query).await?;

    let Some(write) = records[0].as_write() else {
        return Err(unexpected!("grant not found"));
    };

    let desc = &write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(unexpected!("missing grant data"));
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

/// Scope of the permission grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Scope {
    /// The interface the permission is applied to.
    pub interface: Interface,

    /// The method the permission is applied to.
    pub method: Method,

    /// Scope protocol variants.
    #[serde(flatten)]
    pub protocol: ScopeProtocol,
}

impl Scope {
    /// Get the scope protocol.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        match &self.protocol {
            ScopeProtocol::Simple { protocol } => protocol.as_deref(),
            ScopeProtocol::Records { protocol, .. } => Some(protocol),
        }
    }

    /// Get records scope options.
    #[must_use]
    pub const fn options(&self) -> Option<&RecordsOptions> {
        match &self.protocol {
            ScopeProtocol::Records { options, .. } => options.as_ref(),
            ScopeProtocol::Simple { .. } => None,
        }
    }
}

/// Scope type variants.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScopeProtocol {
    /// Protocol is a URI reference
    Simple {
        #[serde(skip_serializing_if = "Option::is_none")]
        /// The protocol the permission is applied to.
        protocol: Option<String>,
    },

    /// `Records` scope fields.
    Records {
        /// The protocol the permission is applied to.
        protocol: String,

        /// Context ID or protocol path.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(flatten)]
        options: Option<RecordsOptions>,
    },
}

impl Default for ScopeProtocol {
    fn default() -> Self {
        Self::Simple { protocol: None }
    }
}

/// Fields specific to the `records` scope.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordsOptions {
    /// The context ID of the record.
    ContextId(String),

    /// The protocol path of the record.
    ProtocolPath(String),
}

impl Default for RecordsOptions {
    fn default() -> Self {
        Self::ContextId(String::new())
    }
}

impl RecordsOptions {
    /// Get the context ID.
    #[must_use]
    pub fn context_id(&self) -> Option<&str> {
        match self {
            Self::ContextId(id) => Some(id),
            Self::ProtocolPath(_) => None,
        }
    }

    /// Get the protocol path.
    #[must_use]
    pub fn protocol_path(&self) -> Option<&str> {
        match self {
            Self::ProtocolPath(path) => Some(path),
            Self::ContextId(_) => None,
        }
    }
}

/// Conditions that must be met when the grant is used.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conditions {
    /// Indicates whether a message written with the invocation of a permission
    /// must, may, or must not be marked as public. If unset, it is optional to
    /// make the message public.
    pub publication: Option<ConditionPublication>,
}

/// Condition for publication of a message.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ConditionPublication {
    /// The message must be marked as public.
    #[default]
    Required,

    /// The message may be marked as public.
    Prohibited,
}

/// A permission request.
pub struct Request {
    /// The ID of the permission request — the record ID DWN message.
    pub id: String,

    /// The requester of the permission.
    pub requestor: String,

    ///used to describe what the requested grant is to be used for.
    pub description: Option<String>,

    /// Whether the requested grant is delegated or not. If `true`, the
    /// `requestor` will be able to act as the grantor of the permission
    /// within the scope of the requested grant.
    pub delegated: Option<bool>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the requested grant is used.
    pub conditions: Option<Conditions>,
}

impl TryFrom<&Write> for Request {
    type Error = crate::Error;

    fn try_from(write: &Write) -> Result<Self> {
        let permission_grant = write.encoded_data.clone().unwrap_or_default();
        let grant_data: GrantData = serde_json::from_str(&permission_grant)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        Ok(Self {
            id: write.record_id.clone(),
            requestor: write.authorization.signer().unwrap_or_default(),
            description: grant_data.description,
            delegated: grant_data.delegated,
            scope: grant_data.scope,
            conditions: grant_data.conditions,
        })
    }
}
