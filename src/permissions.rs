//! # Grant

pub mod grant;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use self::grant::{Grant, GrantBuilder};
use crate::protocols::Definition;
use crate::provider::MessageStore;
use crate::{unexpected, Interface, Method, Result};

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    owner: &str, grant_id: &str, store: &impl MessageStore,
) -> Result<Grant> {
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{grant_id}'
        AND queryable = true
        ",
        interface = Interface::Records,
        method = Method::Write,
    );
    let (messages, _) = store.query(owner, &sql).await?;

    let Some(write) = messages[0].as_write() else {
        return Err(unexpected!("grant not found"));
    };
    let desc = &write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(unexpected!("missing grant data"));
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

/// Protocol for managing web node permission grants.
pub struct Protocol {
    /// The URI of the web node Permissions protocol.
    pub uri: String,

    /// The protocol path of the `request` record.
    pub request_path: String,

    /// The protocol path of the `grant` record.
    pub grant_path: String,

    /// The protocol path of the `revocation` record.
    pub revocation_path: String,

    /// Permissions protocol definition.
    pub definition: Definition,
}

/// Type for the data payload of a permission request message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestData {
    /// If the grant is a delegated grant or not. If `true`, `granted_to` will
    /// be able to act as the `granted_by` within the scope of this grant.
    pub delegated: bool,

    /// Optional string that communicates what the grant would be used for.
    pub description: Option<String>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// Type for the data payload of a permission revocation message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationData {
    /// Optional string that communicates the details of the revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Permission grant message payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantData {
    /// Describes intended grant use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// CID of permission request. Optional as grants may be given without
    /// being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Datetime when grant expires.
    pub date_expires: DateTime<Utc>,

    /// Whether grant is delegated or not. When `true`, the `granted_to` acts
    /// as the `granted_to` within the scope of the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
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

    /// `MessageType` scope fields.
    MessageType {
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
