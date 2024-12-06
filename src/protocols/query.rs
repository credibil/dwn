//! # Protocols Query

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::protocols::{Configure, ProtocolsFilter};
use crate::provider::{MessageStore, Provider, Signer};
use crate::store::{self, Cursor};
use crate::{Descriptor, Interface, Method, Result, permissions, schema, utils};

/// Process query message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    // validate query
    if let Some(filter) = &query.descriptor.filter {
        utils::validate_url(&filter.protocol)?;
    }

    // build actual query
    let mut store_query = store::ProtocolsQuery::from(query.clone());

    // unauthorized queries can query for published protocols
    if !query.authorize(owner, provider).await? {
        store_query.published = Some(true);
    };

    let (records, _) = MessageStore::query(provider, owner, &store_query.into()).await?;

    // unpack messages
    let mut entries = vec![];
    for record in records {
        entries.push(Configure::try_from(record)?);
    }

    Ok(Reply {
        status: Status {
            code: 200,
            detail: Some("OK".to_string()),
        },
        body: Some(QueryReply {
            entries: Some(entries),
            cursor: None,
        }),
    })
}

/// Protocols Query payload
///
/// # Errors
/// TODO: Add errors
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

#[async_trait]
impl Message for Query {
    type Reply = QueryReply;

    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

/// Query reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryReply {
    /// `ProtocolsConfigure` entries matching the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<Configure>>,

    /// Pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

// Fetch published protocols matching the filter
pub(super) async fn fetch_config(
    owner: &str, protocol: Option<String>, store: &impl MessageStore,
) -> Result<Option<Vec<Configure>>> {
    // build query
    let query = store::ProtocolsQuery {
        protocol,
        published: None,
    };

    // execute query
    let (messages, _) = store.query(owner, &query.into()).await?;
    if messages.is_empty() {
        return Ok(None);
    }

    // unpack messages
    let mut entries = vec![];
    for message in messages {
        entries.push(Configure::try_from(message)?);
    }

    Ok(Some(entries))
}

impl Query {
    /// Check message has sufficient privileges.
    ///
    /// # Errors
    /// TODO: Add errors
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<bool> {
        let Some(authzn) = &self.authorization else {
            return Ok(false);
        };

        if authzn.author()? == owner {
            return Ok(true);
        }

        // does the message have a permission grant?
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Ok(false);
        };

        // verify permission grant
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, self.descriptor(), store).await?;

        // if set, query and grant protocols need to match
        let Some(protocol) = grant.data.scope.protocol() else {
            return Ok(true);
        };
        // has a grant but no filter: published protocols only
        let Some(filter) = &self.descriptor.filter else {
            return Ok(false);
        };
        // filter protocol must match grant protocol
        if protocol != filter.protocol {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<ProtocolsFilter>,
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
    /// TODO: Add errors
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
    /// TODO: Add errors
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
