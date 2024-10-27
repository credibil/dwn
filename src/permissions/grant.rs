//! # Grant

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messages::{Direction, Sort};
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::{Descriptor, Interface, Method};

/// Used to grant another entity permission to access a web node's data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct Grant {
    /// The ID of the permission grant — the record ID message.
    pub id: String,

    /// The grantor of the permission.
    pub grantor: String,

    /// The grantee of the permission.
    pub grantee: String,

    /// The date at which the grant was given.
    pub date_granted: String,

    /// The grant's descriptor.
    #[serde(flatten)]
    pub data: GrantData,
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

/// Scope of the permission grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Scope {
    /// The interface the permission is applied to.
    pub interface: Interface,

    /// The method the permission is applied to.
    pub method: Method,

    /// The protocol the permission is applied to. This connects
    /// the grant to protocol access rules, formats, etc.
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

impl Grant {
    /// Validate message is sufficiently authorized.
    ///
    /// Does not validate grant `conditions` or `scope` beyond `interface` and
    /// `method`.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn verify(
        &self, grantor: &str, grantee: &str, descriptor: &Descriptor, provider: &impl Provider,
    ) -> Result<()> {
        // verify the `grantee` against intended recipient
        if grantee != self.grantee {
            return Err(anyhow!("grant not granted to {grantee}"));
        }

        // verifies `grantor` against actual signer
        if grantor != self.grantor {
            return Err(anyhow!("grant not granted by {grantor}"));
        }

        // verify grant scope for interface
        if descriptor.interface != self.data.scope.interface {
            return Err(anyhow!("message interface not within the scope of grant {}", self.id));
        }

        // verify grant scope method
        if descriptor.method != self.data.scope.method {
            return Err(anyhow!("message method not within the scope of grant {}", self.id));
        }

        // verify the message is within the grant's time frame
        let Some(timestamp) = &descriptor.message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };
        self.is_current(grantor, timestamp, provider).await?;

        Ok(())
    }

    /// Verify that the message is within the allowed time frame of the grant, and
    /// the grant has not been revoked.
    async fn is_current(
        &self, grantor: &str, timestamp: &str, store: &impl MessageStore,
    ) -> Result<()> {
        // TODO: use chrono dattime for compare
        // Check that message is within the grant's time frame
        if timestamp < self.date_granted.as_str() {
            return Err(anyhow!("grant is not yet active"));
        }
        if timestamp >= self.data.date_expires.as_str() {
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
        let (messages, _) = store.query(grantor, vec![qf], sort, None).await?;
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
