//! # Messages Query

use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use super::MessagesFilter;
use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::provider::{EventLog, Provider, Signer};
use crate::store::{Cursor, MessagesQuery};
use crate::{Descriptor, Interface, Method, Result, forbidden, permissions, schema};

/// Handle a query message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    query.authorize(owner, provider).await?;

    // FIXME: use pagination cursor
    let query = MessagesQuery::from(query);
    let (events, _) = EventLog::query(provider, owner, &query.into()).await?;

    let events =
        events.iter().map(|e| e.cid().unwrap_or_else(|_| String::new())).collect::<Vec<String>>();
    let entries = if events.is_empty() { None } else { Some(events) };

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(QueryReply {
            entries,
            cursor: None,
        }),
    })
}

/// `Query` payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The `Query` descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

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

impl Query {
    async fn authorize(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        let authzn = &self.authorization;

        let author = authzn.author()?;
        if author == owner {
            return Ok(());
        }

        // verify grant
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Err(forbidden!("author has no grant"));
        };
        let grant = permissions::fetch_grant(owner, grant_id, provider).await?;
        grant.verify(owner, &authzn.signer()?, self.descriptor(), provider).await?;

        // verify filter protocol
        if grant.data.scope.protocol().is_none() {
            return Ok(());
        };

        let protocol = grant.data.scope.protocol();
        for filter in &self.descriptor.filters {
            if filter.protocol.as_deref() != protocol {
                return Err(forbidden!("filter and grant protocols do not match"));
            }
        }

        Ok(())
    }
}
/// `Query` reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct QueryReply {
    /// Entries matching the message's query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// `Query` descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<MessagesFilter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

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
