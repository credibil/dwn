//! # Grant

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use credibil_infosec::Signer;

use crate::client::records::{Data, ProtocolBuilder, WriteBuilder};
pub use crate::grants::{Conditions, Publication, RecordsScope, Scope};
use crate::grants::{GrantData, RequestData, RevocationData};
use crate::interfaces::protocols;
use crate::interfaces::records::{self, Write};
use crate::{Interface, utils};

/// Options to use when creating a permission grant.
pub struct GrantBuilder<G, C, S> {
    granted_to: G,
    date_expires: DateTime<Utc>,
    request_id: Option<String>,
    description: Option<String>,
    delegated: Option<bool>,
    scope: C,
    conditions: Option<Conditions>,
    signer: S,
}

/// Builder state is unsigned.
#[doc(hidden)]
pub struct Unsigned;
/// Builder state is signed.
#[doc(hidden)]
pub struct Signed<'a, S: Signer>(pub &'a S);

/// Builder state has no Scope.
#[doc(hidden)]
pub struct Unscoped;
/// Builder state has a Scope.
#[doc(hidden)]
pub struct Scoped(Scope);

/// Builder state has no grantee.
#[doc(hidden)]
pub struct NoGrantee;
/// Builder state has a grantee.
#[doc(hidden)]
pub struct Grantee(String);

impl Default for GrantBuilder<NoGrantee, Unscoped, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl GrantBuilder<NoGrantee, Unscoped, Unsigned> {
    /// Returns a new [`GrantBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            granted_to: NoGrantee,
            date_expires: Utc::now() + Duration::hours(24),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            description: None,
            delegated: None,
            scope: Unscoped,
            conditions: None,
            signer: Unsigned,
        }
    }
}

impl<C> GrantBuilder<NoGrantee, C, Unsigned> {
    /// Specify who the grant is issued to.
    #[must_use]
    pub fn granted_to(self, granted_to: impl Into<String>) -> GrantBuilder<Grantee, C, Unsigned> {
        GrantBuilder {
            granted_to: Grantee(granted_to.into()),

            date_expires: self.date_expires,
            request_id: self.request_id,
            description: self.description,
            delegated: self.delegated,
            scope: self.scope,
            conditions: self.conditions,
            signer: Unsigned,
        }
    }
}

impl<G> GrantBuilder<G, Unscoped, Unsigned> {
    /// Specify the scope of the grant.
    #[must_use]
    pub fn scope(self, scope: Scope) -> GrantBuilder<G, Scoped, Unsigned> {
        GrantBuilder {
            scope: Scoped(scope),

            granted_to: self.granted_to,
            date_expires: self.date_expires,
            request_id: self.request_id,
            description: self.description,
            delegated: self.delegated,
            conditions: self.conditions,
            signer: Unsigned,
        }
    }
}

impl<G, C> GrantBuilder<G, C, Unsigned> {
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

    /// Specify conditions that must be met when the grant is used.
    #[must_use]
    pub const fn conditions(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }
}

impl GrantBuilder<Grantee, Scoped, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> GrantBuilder<Grantee, Scoped, Signed<'_, S>> {
        GrantBuilder {
            signer: Signed(signer),

            granted_to: self.granted_to,
            date_expires: self.date_expires,
            request_id: self.request_id,
            description: self.description,
            delegated: self.delegated,
            scope: self.scope,
            conditions: self.conditions,
        }
    }
}

impl<S: Signer> GrantBuilder<Grantee, Scoped, Signed<'_, S>> {
    /// Generate a permission grant.
    ///
    /// # Errors
    ///
    /// This method will fail when required grant settings are missing or there
    /// is an issue authorizing the revocation message.
    pub async fn build(self) -> Result<records::Write> {
        let scope = self.scope.0;
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
            .recipient(self.granted_to.0)
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
            let protocol = utils::uri::clean(protocol)?;
            builder = builder.add_tag("protocol", protocol);
        }

        let mut write = builder.sign(self.signer.0).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

        Ok(write)
    }
}

/// Options to use when creating a permission grant.
pub struct RequestBuilder<C, S> {
    description: Option<String>,
    delegated: Option<bool>,
    scope: C,
    conditions: Option<Conditions>,
    signer: S,
}

impl Default for RequestBuilder<Unscoped, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl RequestBuilder<Unscoped, Unsigned> {
    /// Returns a new [`RequestBuilder`]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            description: None,
            delegated: None,
            scope: Unscoped,
            conditions: None,
            signer: Unsigned,
        }
    }

    /// Specify the scope of the grant.
    #[must_use]
    pub fn scope(self, scope: Scope) -> RequestBuilder<Scoped, Unsigned> {
        RequestBuilder {
            scope: Scoped(scope),
            description: self.description,
            delegated: self.delegated,
            conditions: self.conditions,
            signer: Unsigned,
        }
    }
}

impl<C> RequestBuilder<C, Unsigned> {
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

    /// Specify conditions that must be met when the grant is used.
    #[must_use]
    pub const fn conditions(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }
}

impl RequestBuilder<Scoped, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> RequestBuilder<Scoped, Signed<'_, S>> {
        RequestBuilder {
            signer: Signed(signer),

            description: self.description,
            delegated: self.delegated,
            scope: self.scope,
            conditions: self.conditions,
        }
    }
}

impl<S: Signer> RequestBuilder<Scoped, Signed<'_, S>> {
    /// Generate a grant request.
    ///
    /// # Errors
    ///
    /// This method will fail when required grant settings are missing or there
    /// is an issue authorizing the request message.
    pub async fn build(self) -> Result<records::Write> {
        let scope = self.scope.0;

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
            let protocol = utils::uri::clean(protocol)?;
            builder = builder.add_tag("protocol", protocol);
        }

        let mut write = builder.sign(self.signer.0).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&request_bytes));

        Ok(write)
    }
}

/// Options to use when creating a permission grant.
pub struct RevocationBuilder<G, S> {
    grant: G,
    description: Option<String>,
    signer: S,
}

/// Builder state has no grantee.
#[doc(hidden)]
pub struct NoGrant;
/// Builder state has a grantee.
#[doc(hidden)]
pub struct Grant(Write);

impl Default for RevocationBuilder<NoGrant, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl RevocationBuilder<NoGrant, Unsigned> {
    /// Returns a new [`RevocationBuilder`]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            grant: NoGrant,
            description: None,
            signer: Unsigned,
        }
    }

    /// The grant to revoke.
    #[must_use]
    pub fn grant(self, grant: Write) -> RevocationBuilder<Grant, Unsigned> {
        RevocationBuilder {
            grant: Grant(grant),
            description: self.description,
            signer: Unsigned,
        }
    }
}

impl<G> RevocationBuilder<G, Unsigned> {
    /// Describe the purpose of the revocation.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

impl RevocationBuilder<Grant, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> RevocationBuilder<Grant, Signed<'_, S>> {
        RevocationBuilder {
            signer: Signed(signer),
            grant: self.grant,
            description: self.description,
        }
    }
}

impl<S: Signer> RevocationBuilder<Grant, Signed<'_, S>> {
    /// Generate a grant revocation.
    ///
    /// # Errors
    ///
    /// The primary reason this method may fail are:
    ///
    /// - The grant data cannot be deserialized from the `encoded_data` property.
    /// - There is an issue authorizing the revocation message.
    pub async fn build(self) -> Result<records::Write> {
        let grant = self.grant.0;

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
            let protocol = utils::uri::clean(protocol)?;
            builder = builder.add_tag("protocol", protocol);
        }

        let mut write = builder.sign(self.signer.0).build().await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&revocation_bytes));

        Ok(write)
    }
}
