//! # Messages Interface
//!
//! The `Messages` interface provides methods to query, read, and subscribe to
//! any DWN message regardless of the interface or method.

use std::str::FromStr;

use ::cid::Cid;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use credibil_identity::SignerExt;
use credibil_se::Signer;

use crate::authorization::AuthorizationBuilder;
use crate::interfaces::Descriptor;
pub use crate::interfaces::messages::{
    MessagesFilter, Query, QueryDescriptor, Read, ReadDescriptor, Subscribe, SubscribeDescriptor,
};
use crate::utils::cid;
use crate::{Interface, Method};

/// Options to use when creating a permission grant.
pub struct QueryBuilder<S> {
    message_timestamp: DateTime<Utc>,
    filters: Option<Vec<MessagesFilter>>,
    permission_grant_id: Option<String>,
    signer: S,
}

/// Builder state is unsigned.
#[doc(hidden)]
pub struct Unsigned;
/// Builder state is signed.
#[doc(hidden)]
pub struct Signed<'a, S: Signer>(pub &'a S);

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
        Self {
            message_timestamp: Utc::now(),
            filters: None,
            permission_grant_id: None,
            signer: Unsigned,
        }
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn add_filter(mut self, filter: MessagesFilter) -> Self {
        self.filters.get_or_insert_with(Vec::new).push(filter);
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
            filters: self.filters,
            permission_grant_id: self.permission_grant_id,
        }
    }
}

impl<S: SignerExt> QueryBuilder<Signed<'_, S>> {
    /// Generate the permission grant.
    ///
    /// # Errors
    ///
    /// The [`QueryBuilder::build`] method will return an error when there is an issue is
    /// ecountered signing the message.
    ///
    /// Schema validation could potentially fail in debug, but this is
    /// considered unlikely due to the use of strongly-typed data structures.
    pub async fn build(self) -> Result<Query> {
        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Messages,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filters: self.filters.unwrap_or_default(),
            cursor: None,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(self.signer.0).await?;

        Ok(Query {
            descriptor,
            authorization,
        })
    }
}

/// Options to use when creating a permission grant.
pub struct ReadBuilder<M, S> {
    message_timestamp: DateTime<Utc>,
    permission_grant_id: Option<String>,
    message_cid: M,
    signer: S,
}

/// Builder state has no message_cid.
#[doc(hidden)]
pub struct NoMessageCid;
/// Builder state has a message_cid.
#[doc(hidden)]
pub struct MessageCid(String);

impl Default for ReadBuilder<NoMessageCid, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for a `MessagesRead` messages.
impl ReadBuilder<NoMessageCid, Unsigned> {
    /// Returns a new [`ReadBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            permission_grant_id: None,
            message_cid: NoMessageCid,
            signer: Unsigned,
        }
    }

    /// Specify the CID of the message to read.
    #[must_use]
    pub fn message_cid(self, message_cid: impl Into<String>) -> ReadBuilder<MessageCid, Unsigned> {
        ReadBuilder {
            message_cid: MessageCid(message_cid.into()),

            message_timestamp: self.message_timestamp,
            permission_grant_id: self.permission_grant_id,
            signer: self.signer,
        }
    }
}

impl<M> ReadBuilder<M, Unsigned> {
    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }
}

impl ReadBuilder<MessageCid, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &S) -> ReadBuilder<MessageCid, Signed<'_, S>> {
        ReadBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            permission_grant_id: self.permission_grant_id,
            message_cid: self.message_cid,
        }
    }
}

impl<S: SignerExt> ReadBuilder<MessageCid, Signed<'_, S>> {
    /// Generate the Read message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue signing the message or
    /// serilaizing the descriptor to CBOR.
    pub async fn build(self) -> Result<Read> {
        // verify CID
        let message_cid = self.message_cid.0;
        let _ = Cid::from_str(&message_cid).context("parsing CID")?;

        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Messages,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            message_cid,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(self.signer.0).await?;

        Ok(Read {
            descriptor,
            authorization,
        })
    }
}

/// Options to use when creating a permission grant.
pub struct SubscribeBuilder<S> {
    message_timestamp: DateTime<Utc>,
    filters: Option<Vec<MessagesFilter>>,
    permission_grant_id: Option<String>,
    signer: S,
}

impl Default for SubscribeBuilder<Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a permission grant.
impl SubscribeBuilder<Unsigned> {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            filters: None,
            permission_grant_id: None,
            signer: Unsigned,
        }
    }

    /// Specify event filter to use when subscribing.
    #[must_use]
    pub fn add_filter(mut self, filter: MessagesFilter) -> Self {
        self.filters.get_or_insert_with(Vec::new).push(filter);
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
    pub fn sign<S: Signer>(self, signer: &S) -> SubscribeBuilder<Signed<'_, S>> {
        SubscribeBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            filters: self.filters,
            permission_grant_id: self.permission_grant_id,
        }
    }
}

impl<S: SignerExt> SubscribeBuilder<Signed<'_, S>> {
    /// Generate the permission grant.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue signing the message or
    /// serilaizing the descriptor to CBOR.
    pub async fn build(self) -> Result<Subscribe> {
        let descriptor = SubscribeDescriptor {
            base: Descriptor {
                interface: Interface::Messages,
                method: Method::Subscribe,
                message_timestamp: self.message_timestamp,
            },
            filters: self.filters.unwrap_or_default(),
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(self.signer.0).await?;

        Ok(Subscribe {
            descriptor,
            authorization,
        })
    }
}
