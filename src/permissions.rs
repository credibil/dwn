//! # Permissions

mod grant;
mod protocol;
mod request;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{
    Grant, GrantBuilder, GrantData, RequestBuilder, RequestData, RevocationData,
};
pub(crate) use self::protocol::{Protocol, fetch_scope};
use crate::provider::MessageStore;
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
        #[serde(skip_serializing_if = "Option::is_none")]
        options: Option<RecordsOptions>,
    },

    /// Scope applies to the `Messages` interface.
    Messages {
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
            options: None,
        }
    }
}

impl Scope {
    /// Get the scope protocol.
    #[must_use]
    pub const fn interface(&self) -> Interface {
        match &self {
            Self::Records { .. } => Interface::Records,
            Self::Messages { .. } => Interface::Messages,
        }
    }

    /// Get the scope method.
    #[must_use]
    pub fn method(&self) -> Method {
        match self {
            Self::Records { method, .. } | Self::Messages { method, .. } => method.clone(),
        }
    }

    /// Get the scope protocol.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        match &self {
            Self::Records { protocol, .. } => Some(protocol),
            Self::Messages { protocol, .. } => protocol.as_deref(),
        }
    }

    // /// Get records scope options.
    // #[must_use]
    // pub const fn options(&self) -> Option<&RecordsOptions> {
    //     match &self.protocol {
    //         Some(ScopeProtocol::Records { options, .. }) => options.as_ref(),
    //         _ => None,
    //     }
    // }
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
