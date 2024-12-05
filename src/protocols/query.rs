//! # Protocols Query

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::protocols::{Configure, ProtocolsFilter};
use crate::provider::{MessageStore, Provider, Signer};
use crate::store::{Cursor, ProtocolsQuery};
use crate::{Descriptor, Interface, Method, Result, forbidden, permissions, schema, utils};

/// Process query message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    query.authorize(owner, provider).await?;
    let entries = fetch_config(owner, query.descriptor.filter, provider).await?;

    Ok(Reply {
        status: Status {
            code: 200,
            detail: Some("OK".to_string()),
        },
        body: Some(QueryReply {
            entries,
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
    pub authorization: Authorization,
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
        Some(&self.authorization)
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

/// Fetch published `protocols::Configure` matching the query
pub async fn fetch_config(
    owner: &str, filter: Option<ProtocolsFilter>, store: &impl MessageStore,
) -> Result<Option<Vec<Configure>>> {
    let mut query = ProtocolsQuery::new(); //.published(true);
    if let Some(filter) = filter {
        let protocol_uri = utils::clean_url(&filter.protocol)?;
        query = query.protocol(&protocol_uri);
    };

    // execute query
    let (messages, _) = store.query(owner, &query.build()).await?;
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
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;

        if authzn.author()? == owner {
            return Ok(());
        }

        // verify grant
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Err(forbidden!("author has no permission grant"));
        };
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, self.descriptor(), store).await?;

        // if set, query and grant protocols need to match
        let Some(protocol) = grant.data.scope.protocol() else {
            return Ok(());
        };
        let Some(filter) = &self.descriptor.filter else {
            return Err(forbidden!("missing filter"));
        };
        if protocol != filter.protocol {
            return Err(forbidden!("unauthorized protocol"));
        }

        Ok(())
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

    /// Generate the permission grant.
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
