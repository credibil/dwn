//! # Grant

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messages::{Direction, Sort};
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::service::Message;
use crate::{Interface, Method};

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    tenant: &str, grant_id: &str, provider: &impl Provider,
) -> Result<Grant> {
    let mut qf = query::Filter {
        criteria: BTreeMap::<String, Criterion>::new(),
    };
    qf.criteria.insert(
        "recordId".to_string(),
        Criterion::Single(Compare::Equal(Value::String(grant_id.to_owned()))),
    );
    qf.criteria.insert(
        "isLatestBaseState".to_string(),
        Criterion::Single(Compare::Equal(Value::Bool(true))),
    );

    // execute query
    let (messages, _) = MessageStore::query(provider, tenant, vec![qf], None, None).await?;
    let message = &messages[0];
    let Message::RecordsWrite(write) = message.clone() else {
        return Err(anyhow!("no permission grant with ID {grant_id}"));
    };
    let desc = write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(anyhow!("missing grant data"));
    };
    let grant_bytes = Base64UrlUnpadded::decode_vec(grant_enc)?;
    let grant: GrantData = serde_json::from_slice(&grant_bytes)?;

    Ok(Grant {
        id: write.record_id,
        grantor: message.signer().unwrap_or_default(),
        grantee: desc.recipient.unwrap_or_default(),
        date_granted: desc.date_created,
        date_expires: grant.date_expires,
        delegated: grant.delegated,
        description: grant.description,
        request_id: grant.request_id,
        scope: grant.scope,
        conditions: grant.conditions,
    })
}

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct Grant {
    /// The ID of the permission grant, which is the record ID DWN message.
    pub id: String,

    /// The grantor of the permission.
    pub grantor: String,

    /// The grantee of the permission.
    pub grantee: String,

    /// The date at which the grant was given.
    pub date_granted: String,

    /// Describes intended grant use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional CID of a permission request. Pptional because grants may be
    /// given without being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Timestamp at which this grant will no longer be active.
    pub date_expires: String,

    /// Whether grant is delegated or not. When `true`, `granted_to` acts as
    /// the `granted_to` within the scope of this grant.
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

    /// The protocol the permission is applied to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Conditions that must be met when the grant is used.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conditions {
    /// indicates whether a message written with the invocation of a permission must, may, or must not
    /// be marked as public.
    /// If `undefined`, it is optional to make the message public.
    pub publication: Option<ConditionPublication>,
}

/// Condition for publication of a message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum ConditionPublication {
    /// The message must be marked as public.
    #[default]
    Required,

    /// The message may be marked as public.
    Prohibited,
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
    pub date_expires: String,

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

impl Grant {
    /// Validate message is sufficiently authorized.
    ///
    /// Does not validate grant `conditions` or `scope` beyond `interface` and
    /// `method`.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn validate(
        &self, grantor: &str, grantee: &str, msg: Message, provider: &impl Provider,
    ) -> Result<()> {
        let desc = msg.descriptor();

        // verify the `grantee` against intended recipient
        if grantee != self.grantee {
            return Err(anyhow!("grant not granted to {grantee}"));
        }

        // verifies `grantor` against actual signer
        if grantor != self.grantor {
            return Err(anyhow!("grant not granted by {grantor}"));
        }

        // verify grant scope for interface
        if desc.interface != self.scope.interface {
            return Err(anyhow!("message interface not within the scope of grant {}", self.id));
        }

        // verify grant scope method
        if desc.method != self.scope.method {
            return Err(anyhow!("message method not within the scope of grant {}", self.id));
        }

        // verify the message is within the grant's time frame
        let Some(timestamp) = &desc.message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };
        self.verify_active(grantor, timestamp, provider).await?;

        Ok(())
    }

    /// Verify that the message is within the allowed time frame of the grant, and
    /// the grant has not been revoked.
    async fn verify_active(
        &self, grantor: &str, timestamp: &str, provider: &impl Provider,
    ) -> Result<()> {
        // Check that message is within the grant's time frame
        if timestamp < &self.date_granted {
            return Err(anyhow!("grant is not yet active"));
        }
        if timestamp >= &self.date_expires {
            return Err(anyhow!("grant has expired"));
        }

        // Check if grant has been revoked
        let mut qf = query::Filter {
            criteria: BTreeMap::<String, Criterion>::new(),
        };
        qf.criteria.insert(
            "parentId".to_string(),
            Criterion::Single(Compare::Equal(Value::String(self.id.clone()))),
        );
        qf.criteria.insert(
            "protocolPath".to_string(),
            Criterion::Single(Compare::Equal(Value::String("grant/revocation".to_string()))),
        );
        qf.criteria.insert(
            "isLatestBaseState".to_string(),
            Criterion::Single(Compare::Equal(Value::Bool(true))),
        );

        // find oldest message in the revocation chain
        let sort = Some(Sort {
            message_timestamp: Some(Direction::Descending),
            ..Default::default()
        });
        let (messages, _) = MessageStore::query(provider, grantor, vec![qf], sort, None).await?;
        let Some(oldest) = messages.first().cloned() else {
            return Err(anyhow!("grant has been revoked"));
        };

        let Some(message_timestamp) = &oldest.descriptor().message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };

        if message_timestamp.as_str() <= timestamp {
            return Err(anyhow!("grant with CID {} has been revoked", self.id));
        }

        Ok(())
    }
}
