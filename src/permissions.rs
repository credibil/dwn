//! # Permissions

pub mod grant;
pub(crate) mod protocol;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{Grant, GrantBuilder};
use crate::provider::MessageStore;
use crate::store::RecordsQuery;
use crate::{unexpected, Interface, Method, Result};

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

    /// Variant scope fields.
    #[serde(flatten)]
    pub scope_type: ScopeType,
}

/// Scope type variants.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScopeType {
    /// `Protocols` scope fields.
    Protocols {
        /// The protocol the permission is applied to.
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
    /// `EntryType` scope fields.
    EntryType {
        /// The protocol the permission is applied to.
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
    /// `Records` scope fields.
    Records {
        /// The protocol the permission is applied to.
        protocol: String,

        /// Context ID or protocol path.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(flatten)]
        option: Option<RecordsOptions>,
    },
}

impl Default for ScopeType {
    fn default() -> Self {
        Self::Protocols { protocol: None }
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
