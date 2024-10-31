//! # Grant

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messages::{Direction, Sort};
use crate::provider::{Keyring, MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::records::{self, WriteBuilder, WriteData, WriteProtocol};
use crate::{protocols, utils, Descriptor, Interface, Method};

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
    pub date_granted: DateTime<Utc>,

    /// The grant's descriptor.
    #[serde(flatten)]
    pub data: GrantData,
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
        &self, grantor: &str, timestamp: &DateTime<Utc>, store: &impl MessageStore,
    ) -> Result<()> {
        // TODO: use chrono dattime for compare
        // Check that message is within the grant's time frame
        if timestamp.lt(&self.date_granted) {
            return Err(anyhow!("grant is not yet active"));
        }
        if timestamp.ge(&self.data.date_expires) {
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
        if message_timestamp.lt(timestamp) {
            return Err(anyhow!("grant with CID {} has been revoked", self.id));
        }

        Ok(())
    }
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

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct GrantBuilder {
    granted_to: String,
    date_expires: DateTime<Utc>,
    request_id: Option<String>,
    description: Option<String>,
    delegated: Option<bool>,
    scope: Option<Scope>,
    conditions: Option<Conditions>,
}

/// Builder for creating a permission grant.
impl GrantBuilder {
    /// Returns a new [`GrantBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            date_expires: Utc::now() + Duration::seconds(100),
            ..Self::default()
        }
    }

    /// Specify who the grant is issued to.
    #[must_use]
    pub fn granted_to(mut self, granted_to: impl Into<String>) -> Self {
        self.granted_to = granted_to.into();
        self
    }

    /// The time in seconds after which the issued grant will expire. Defaults
    /// to 100 seconds.
    #[must_use]
    pub fn expires_in(mut self, seconds: i64) -> Self {
        if seconds <= 0 {
            return self;
        }
        self.date_expires = Utc::now() + Duration::seconds(seconds);
        self
    }

    /// Specify an ID to use for the permission request.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Describe the purpose of the grant.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Specify whether the grant is delegated or not.
    #[must_use]
    pub const fn delegated(mut self, delegated: bool) -> Self {
        self.delegated = Some(delegated);
        self
    }

    /// Specify the scope of the grant.
    #[must_use]
    pub fn scope(mut self, interface: Interface, method: Method, protocol: Option<String>) -> Self {
        self.scope = Some(Scope {
            interface,
            method,
            protocol,
        });
        self
    }

    /// Specify conditions that must be met when the grant is used.
    #[must_use]
    pub const fn conditions(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, keyring: &impl Keyring) -> Result<records::Write> {
        if self.granted_to.is_empty() {
            return Err(anyhow!("missing `granted_to`"));
        }
        let Some(scope) = self.scope else {
            return Err(anyhow!("missing `scope`"));
        };

        let grant_bytes = serde_json::to_vec(&GrantData {
            date_expires: self.date_expires,
            request_id: self.request_id,
            description: self.description,
            delegated: self.delegated,
            scope: scope.clone(),
            conditions: self.conditions,
        })?;

        let mut builder = WriteBuilder::new()
            .recipient(self.granted_to)
            .protocol(WriteProtocol {
                protocol: protocols::PROTOCOL_URI.to_string(),
                protocol_path: "grant".to_string(),
            })
            .data(WriteData::Bytes {
                data: grant_bytes.clone(),
            });

        if let Some(protocol) = &scope.protocol {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.build(keyring).await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

        Ok(write)
    }
}
