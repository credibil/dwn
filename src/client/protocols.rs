//! # Protocols Interface
//!
//! DWN nodes provide the substrate upon which a wide variety of decentralized
//! applications and services can be implemented. By employing protocols, DWN
//! owners can define the rules and constraints that govern the behavior of the
//! data stored on their nodes.
//!
//! Protocols provide a mechanism for declaratively encoding an app or
//! service’s rules, including segmentation of records, relationships
//! between records, data-level requirements, and constraints on how
//! DWN users interact with a protocol.
//!
//! DWN owners can model the protocols for a wide array of use cases in a way
//! that enables interop-by-default between app implementations built on top of
//! them.
//!
//! The Protocols client provides a builder and related types to use in
//! building Protocol-related messages (Configure and Query).

#![cfg(feature = "client")]

use chrono::{DateTime, Utc};
use credibil_infosec::Signer;

use crate::authorization::AuthorizationBuilder;
use crate::interfaces::Descriptor;
pub use crate::interfaces::protocols::{
    self, Action, ActionRule, Actor, Configure, ConfigureDescriptor, Definition, ProtocolType,
    ProtocolsFilter, Query, QueryDescriptor, RuleSet, Size,
};
use crate::interfaces::records::DelegatedGrant;
use crate::utils::cid;
use crate::{Interface, Method, Result, utils};

/// Options to use when creating a permission grant.
pub struct ConfigureBuilder<D, S> {
    message_timestamp: DateTime<Utc>,
    definition: D,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,
    signer: S,
}

/// Builder state is unsigned.
#[doc(hidden)]
pub struct Unsigned;
/// Builder state is signed.
#[doc(hidden)]
pub struct Signed<'a, S: Signer>(pub &'a S);

/// Builder state has no Definition.
#[doc(hidden)]
pub struct Undefined;
/// Builder state has a Definition.
#[doc(hidden)]
pub struct Defined(Definition);

impl Default for ConfigureBuilder<Undefined, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl ConfigureBuilder<Undefined, Unsigned> {
    /// Returns a new [`ConfigureBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            definition: Undefined,
            delegated_grant: None,
            permission_grant_id: None,
            signer: Unsigned,
        }
    }

    /// Specify the protocol's definition.
    #[must_use]
    pub fn definition(self, definition: Definition) -> ConfigureBuilder<Defined, Unsigned> {
        ConfigureBuilder {
            message_timestamp: self.message_timestamp,
            definition: Defined(definition),
            delegated_grant: self.delegated_grant,
            permission_grant_id: self.permission_grant_id,
            signer: Unsigned,
        }
    }
}

impl<D> ConfigureBuilder<D, Unsigned> {
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

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> ConfigureBuilder<D, Signed<'_, S>> {
        ConfigureBuilder {
            signer: Signed(signer),
            message_timestamp: self.message_timestamp,
            definition: self.definition,
            delegated_grant: self.delegated_grant,
            permission_grant_id: self.permission_grant_id,
        }
    }
}

impl<S: Signer> ConfigureBuilder<Defined, Signed<'_, S>> {
    /// Generate the Configure message.
    ///
    /// # Errors
    ///
    /// This method will fail when an invalid Definition is provided or there
    /// is an issue authorizing the message.
    pub async fn build(self) -> Result<Configure> {
        // normalize definition urls
        let mut definition = self.definition.0;
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
        let authorization = builder.build(self.signer.0).await?;

        // if cfg!(feature = "client") {
        //     Ok(Configure {
        //         descriptor,
        //         authorization,
        //     })
        // } else {
        // #[allow(clippy::needless_update)]
        Ok(Configure {
            descriptor,
            authorization,
            ..Configure::default()
        })
        // }
    }
}

/// Options to use when creating a permission grant.
pub struct QueryBuilder<S> {
    message_timestamp: DateTime<Utc>,
    filter: Option<ProtocolsFilter>,
    permission_grant_id: Option<String>,
    signer: S,
}

impl Default for QueryBuilder<Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl QueryBuilder<Unsigned> {
    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            filter: None,
            permission_grant_id: None,
            signer: Unsigned,
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

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> QueryBuilder<Signed<'_, S>> {
        QueryBuilder {
            signer: Signed(signer),
            message_timestamp: self.message_timestamp,
            filter: self.filter,
            permission_grant_id: self.permission_grant_id,
        }
    }

    /// Build an anonymous query.
    #[must_use]
    pub fn build(self) -> Query {
        Query {
            descriptor: QueryDescriptor {
                base: Descriptor {
                    interface: Interface::Protocols,
                    method: Method::Query,
                    message_timestamp: self.message_timestamp,
                },
                filter: self.filter,
            },
            authorization: None,
        }
    }
}

impl<S: Signer> QueryBuilder<Signed<'_, S>> {
    /// Build the query.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue authorizing the message.
    pub async fn build(self) -> Result<Query> {
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

        Ok(Query {
            descriptor,
            authorization: Some(authorization.build(self.signer.0).await?),
        })
    }
}
