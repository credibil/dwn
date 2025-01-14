//! # Messages Query

use anyhow::Result;
use chrono::{DateTime, Utc};
use dwn_node::authorization::AuthorizationBuilder;
use dwn_node::messages::{MessagesFilter, Query, QueryDescriptor};
use dwn_node::{Descriptor, Interface, Method, schema};

use crate::data::cid;
use crate::provider::Signer;

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
