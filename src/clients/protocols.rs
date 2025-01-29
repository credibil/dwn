//! # Protocols Client
//!
//! The Protocols client provides a builder and related types to use in
//! building Protocol-related messages (Configure and Query).

use chrono::{DateTime, Utc};

use crate::authorization::AuthorizationBuilder;
pub use crate::protocols::{
    self, Configure, ConfigureDescriptor, Definition, ProtocolsFilter, Query, QueryDescriptor,
};
use crate::provider::Signer;
use crate::records::DelegatedGrant;
use crate::utils::cid;
use crate::{Descriptor, Interface, Method, Result, schema, unexpected, utils};

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ConfigureBuilder {
    message_timestamp: DateTime<Utc>,
    definition: Option<Definition>,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl ConfigureBuilder {
    /// Returns a new [`ConfigureBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specify the protocol's definition.
    #[must_use]
    pub fn definition(mut self, definition: Definition) -> Self {
        self.definition = Some(definition);
        self
    }

    /// The delegated grant invoked to sign on behalf of the logical author,
    /// who is the grantor of the delegated grant.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Generate the Configure message body..
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Configure> {
        // check definition has been set
        let mut definition = self.definition.ok_or_else(|| unexpected!("definition not found"))?;

        // normalize definition urls
        definition.protocol = utils::uri::clean(&definition.protocol)?;
        for t in definition.types.values_mut() {
            if let Some(schema) = &t.schema {
                t.schema = Some(utils::uri::clean(schema)?);
            }
        }
        protocols::validate_structure(&definition)?;

        let descriptor = ConfigureDescriptor {
            base: Descriptor {
                interface: Interface::Protocols,
                method: Method::Configure,
                message_timestamp: self.message_timestamp,
            },
            definition,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(permission_grant_id) = self.permission_grant_id {
            builder = builder.permission_grant_id(permission_grant_id);
        }
        if let Some(delegated_grant) = self.delegated_grant {
            builder = builder.delegated_grant(delegated_grant);
        }
        let authorization = builder.build(signer).await?;

        let configure = Configure {
            descriptor,
            authorization,
        };

        // TODO: move validation out of message
        schema::validate(&configure)?;

        Ok(configure)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct QueryBuilder {
    message_timestamp: DateTime<Utc>,
    filter: Option<ProtocolsFilter>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl QueryBuilder {
    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn filter(mut self, protocol: impl Into<String>) -> Self {
        self.filter = Some(ProtocolsFilter {
            protocol: protocol.into(),
        });
        self
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Build the query.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Query> {
        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Protocols,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter,
        };

        let mut authorization =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            authorization = authorization.permission_grant_id(id);
        }

        let query = Query {
            descriptor,
            authorization: Some(authorization.build(signer).await?),
        };

        schema::validate(&query)?;

        Ok(query)
    }

    /// Build an anonymous query.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn anonymous(self) -> Result<Query> {
        let query = Query {
            descriptor: QueryDescriptor {
                base: Descriptor {
                    interface: Interface::Protocols,
                    method: Method::Query,
                    message_timestamp: self.message_timestamp,
                },
                filter: self.filter,
            },
            authorization: None,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}
