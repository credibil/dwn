//! # Grant

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ConditionPublication, Conditions, GrantData, RecordsOptions, Scope, ScopeType};
use crate::protocols::{self, REVOCATION_PATH};
use crate::provider::{Keyring, MessageStore};
use crate::records::{self, Delete, Write, WriteBuilder, WriteData, WriteProtocol};
use crate::{unexpected, utils, Descriptor, Interface, Method, Result};

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
        &self, grantor: &str, grantee: &str, descriptor: &Descriptor, store: &impl MessageStore,
    ) -> Result<()> {
        // verify the `grantee` against intended recipient
        if grantee != self.grantee {
            return Err(unexpected!("grant not granted to {grantee}"));
        }

        // verifies `grantor` against actual signer
        if grantor != self.grantor {
            return Err(unexpected!("grant not granted by {grantor}"));
        }

        // verify grant scope for interface
        if descriptor.interface != self.data.scope.interface {
            return Err(unexpected!("interface not within the scope of grant {}", self.id,));
        }

        // verify grant scope method
        if descriptor.method != self.data.scope.method {
            return Err(unexpected!("method not within the scope of grant {}", self.id,));
        }

        // verify the message is within the grant's time frame
        let Some(timestamp) = &descriptor.message_timestamp else {
            return Err(unexpected!("missing message timestamp"));
        };
        self.is_current(grantor, timestamp, store).await?;

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
            return Err(unexpected!("grant is not yet active"));
        }
        if timestamp.ge(&self.data.date_expires) {
            return Err(unexpected!("grant has expired"));
        }

        // Check if grant has been revoked — using latest revocation message
        let sql = format!(
            "
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'
            AND descriptor.parentId = '{parent_id}'
            AND descriptor.protocolPath = '{REVOCATION_PATH}'
            AND lastestBase = true
            ORDER BY descriptor.messageTimestamp DESC
            ",
            interface = Interface::Records,
            method = Method::Write,
            parent_id = self.id
        );

        let (messages, _) = store.query(grantor, &sql).await?;
        let Some(oldest) = messages.first().cloned() else {
            return Err(unexpected!("grant has been revoked"));
        };
        let Some(message_timestamp) = &oldest.descriptor().message_timestamp else {
            return Err(unexpected!("missing message timestamp"));
        };
        if message_timestamp.lt(timestamp) {
            return Err(unexpected!("grant with CID {} has been revoked", self.id));
        }

        Ok(())
    }

    /// Verify the grant allows the `records::Write` message to be written.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn permit_records_write(
        &self, grantor: &str, grantee: &str, write: &Write, store: &impl MessageStore,
    ) -> Result<()> {
        self.verify(grantor, grantee, &write.descriptor.base, store).await?;
        self.verify_scope(write)?;
        self.verify_conditions(write)?;
        Ok(())
    }

    /// Verify the grant allows the `records::Write` message to be deleted.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn permit_records_delete(
        &self, grantor: &str, grantee: &str, delete: &Delete, write: &Write,
        store: &impl MessageStore,
    ) -> Result<()> {
        self.verify(grantor, grantee, &delete.descriptor.base, store).await?;

        // must be deleting a record with the same protocol
        if let ScopeType::Protocols { protocol } = &self.data.scope.scope_type {
            if protocol != &write.descriptor.protocol {
                return Err(unexpected!("grant and record to delete protocol do not match"));
            }
        };

        Ok(())
    }

    pub(crate) fn verify_scope(&self, write: &Write) -> Result<()> {
        let ScopeType::Records { protocol, option } = &self.data.scope.scope_type else {
            return Err(unexpected!("invalid scope type"));
        };
        if Some(protocol) != write.descriptor.protocol.as_ref() {
            return Err(unexpected!("incorrect scope `protocol`"));
        }
        let Some(option) = option else {
            return Ok(());
        };

        match option {
            RecordsOptions::ContextId(context_id) => {
                if Some(context_id) != write.context_id.as_ref() {
                    return Err(unexpected!("incorrect scope `context_id`"));
                }
            }
            RecordsOptions::ProtocolPath(protocol_path) => {
                if Some(protocol_path) != write.descriptor.protocol_path.as_ref() {
                    return Err(unexpected!("incorrect scope `protocol_path`"));
                }
            }
        }

        Ok(())
    }

    fn verify_conditions(&self, write: &Write) -> Result<()> {
        let Some(conditions) = &self.data.conditions else {
            return Ok(());
        };
        let Some(publication) = &conditions.publication else {
            return Ok(());
        };

        let published = write.descriptor.published.unwrap_or_default();
        match publication {
            ConditionPublication::Required => {
                if !published {
                    return Err(unexpected!("grant requires message to be published",));
                }
            }
            ConditionPublication::Prohibited => {
                if published {
                    return Err(unexpected!("grant prohibits publishing message",));
                }
            }
        }

        Ok(())
    }
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
    pub fn scope(mut self, interface: Interface, method: Method, scope_type: ScopeType) -> Self {
        self.scope = Some(Scope {
            interface,
            method,
            scope_type,
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
            return Err(unexpected!("missing `granted_to`"));
        }
        let Some(scope) = self.scope else {
            return Err(unexpected!("missing `scope`"));
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

        // add protocol tag
        let protocol = match &scope.scope_type {
            ScopeType::Protocols { protocol } | ScopeType::MessageType { protocol } => {
                protocol.as_ref()
            }
            ScopeType::Records { protocol, .. } => Some(protocol),
        };
        if let Some(protocol) = protocol {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.build(keyring).await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

        Ok(write)
    }
}
