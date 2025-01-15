//! # Grant

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::clients::records::{Data, ProtocolBuilder, WriteBuilder};
use crate::permissions::{Conditions, GrantData, RequestData, RevocationData, Scope};
use crate::protocols::{self};
use crate::provider::Keyring;
use crate::records::{self, Write};
use crate::{Interface, utils};

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
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            date_expires: Utc::now() + Duration::hours(24),
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
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
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
    /// LATER: Add errors
    pub async fn build(self, keyring: &impl Keyring) -> Result<records::Write> {
        let Some(scope) = self.scope else {
            return Err(anyhow!("missing `scope`"));
        };
        if self.granted_to.is_empty() {
            return Err(anyhow!("missing `granted_to`"));
        }
        if scope.interface() == Interface::Records && scope.protocol().is_none() {
            return Err(anyhow!("`Records` scope must have protocol set"));
        }

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
            .protocol(ProtocolBuilder {
                protocol: protocols::PROTOCOL_URI,
                protocol_path: protocols::GRANT_PATH,
                parent_context_id: None,
            })
            .data(Data::from(grant_bytes.clone()));

        // add protocol tag
        // N.B. adding a protocol tag ensures message queries with a protocol
        // filter will return associated grants
        if let Some(protocol) = scope.protocol() {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.sign(keyring).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

        Ok(write)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct RequestBuilder {
    description: Option<String>,
    delegated: Option<bool>,
    scope: Option<Scope>,
    conditions: Option<Conditions>,
}

/// Builder for creating a permission grant.
impl RequestBuilder {
    /// Returns a new [`RequestBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
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
    /// LATER: Add errors
    pub async fn build(self, keyring: &impl Keyring) -> Result<records::Write> {
        let Some(scope) = self.scope else {
            return Err(anyhow!("missing `scope`"));
        };

        let request_bytes = serde_json::to_vec(&RequestData {
            description: self.description,
            delegated: self.delegated.unwrap_or_default(),
            scope: scope.clone(),
            conditions: self.conditions,
        })?;

        let mut builder = WriteBuilder::new()
            .protocol(ProtocolBuilder {
                protocol: protocols::PROTOCOL_URI,
                protocol_path: protocols::REQUEST_PATH,
                parent_context_id: None,
            })
            .data(Data::from(request_bytes.clone()));

        // add protocol tag
        // N.B. adding a protocol tag ensures message queries with a protocol
        // filter will return this request
        if let Some(protocol) = scope.protocol() {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.sign(keyring).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&request_bytes));

        Ok(write)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct RevocationBuilder {
    grant: Option<Write>,
    description: Option<String>,
}

/// Builder for creating a permission grant.
impl RevocationBuilder {
    /// Returns a new [`RevocationBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The grant to revoke.
    #[must_use]
    pub fn grant(mut self, grant: Write) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, keyring: &impl Keyring) -> Result<records::Write> {
        let Some(grant) = self.grant else {
            return Err(anyhow!("missing `grant`"));
        };

        let Some(encoded) = &grant.encoded_data else {
            return Err(anyhow!("missing grant data"));
        };
        let grant_bytes = Base64UrlUnpadded::decode_vec(encoded)?;
        let grant_data: GrantData = serde_json::from_slice(&grant_bytes)?;

        let revocation_bytes = serde_json::to_vec(&RevocationData {
            description: self.description,
        })?;

        let mut builder = WriteBuilder::new()
            .protocol(ProtocolBuilder {
                protocol: protocols::PROTOCOL_URI,
                protocol_path: protocols::REVOCATION_PATH,
                parent_context_id: Some(grant.record_id.clone()),
            })
            .data(Data::from(revocation_bytes.clone()));

        // add protocol tag
        // N.B. adding a protocol tag ensures message queries with a protocol
        // filter will return this request
        if let Some(protocol) = grant_data.scope.protocol() {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.sign(keyring).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&revocation_bytes));

        Ok(write)
    }
}
