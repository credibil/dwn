//! # Messages Query

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use super::MessagesFilter;
use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Context, Message, Reply, Status};
use crate::permissions::{self, ScopeType};
use crate::provider::{EventLog, MessageStore, Provider, Signer};
use crate::store::{Cursor, MessagesQuery};
use crate::{forbidden, schema, Descriptor, Interface, Method, Result};

/// Handle a query message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    query.authorize(owner, provider).await?;

    // TODO: use pagination cursor
    let query = MessagesQuery::from(query).build();
    let (events, _) = EventLog::query(provider, owner, &query).await?;

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

    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(&ctx.owner, self, provider).await
    }
}

impl Query {
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = authzn.author()?;

        if author == owner {
            return Ok(());
        }

        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Ok(());
        };

        // verify grant
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(&author, &authzn.signer()?, self.descriptor(), store).await?;

        // ensure query filters include scoped protocol
        let ScopeType::Protocols { protocol } = &grant.data.scope.scope_type else {
            return Err(forbidden!("missing protocol scope"));
        };

        if protocol.is_none() {
            return Ok(());
        }

        for filter in &self.descriptor.filters {
            if &filter.protocol != protocol {
                return Err(forbidden!("filter protocol does not match scoped protocol",));
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
    message_timestamp: Option<DateTime<Utc>>,
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
            message_timestamp: Some(Utc::now()),
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

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
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
