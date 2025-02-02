//! # Messages Query

use std::str::FromStr;

use ::cid::Cid;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

use crate::authorization::AuthorizationBuilder;
pub use crate::messages::MessagesFilter;
use crate::messages::{
    Query, QueryDescriptor, Read, ReadDescriptor, Subscribe, SubscribeDescriptor,
};
use crate::provider::Signer;
use crate::utils::cid;
use crate::{Descriptor, Interface, Method, schema};

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct QueryBuilder {
    message_timestamp: DateTime<Utc>,
    filters: Option<Vec<MessagesFilter>>,
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

    // FIXME: move signer to .sign(signer) method

    /// Generate the permission grant.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Query> {
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
        let authorization = builder.build(signer).await?;

        let query = Query {
            descriptor,
            authorization,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ReadBuilder {
    message_timestamp: DateTime<Utc>,
    permission_grant_id: Option<String>,
    message_cid: Option<String>,
}

/// Builder for creating a permission grant.
impl ReadBuilder {
    /// Returns a new [`ReadBuilder`]
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
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify the CID of the message to read.
    #[must_use]
    pub fn message_cid(mut self, message_cid: impl Into<String>) -> Self {
        self.message_cid = Some(message_cid.into());
        self
    }

    /// Generate the Read message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Read> {
        // verify CID
        let Some(message_cid) = self.message_cid else {
            return Err(anyhow!("missing message CID"));
        };
        let _ = Cid::from_str(&message_cid).map_err(|e| anyhow!("invalid CID: {e}"))?;

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
        let authorization = builder.build(signer).await?;

        let read = Read {
            descriptor,
            authorization,
        };

        schema::validate(&read)?;

        Ok(read)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct SubscribeBuilder {
    message_timestamp: DateTime<Utc>,
    filters: Option<Vec<MessagesFilter>>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl SubscribeBuilder {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
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

    /// Generate the permission grant.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Subscribe> {
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
        let authorization = builder.build(signer).await?;

        let query = Subscribe {
            descriptor,
            authorization,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}
