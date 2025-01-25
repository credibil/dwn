//! # Messages Query

use http::StatusCode;
use serde::{Deserialize, Serialize};

use super::MessagesFilter;
use crate::authorization::Authorization;
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::provider::{EventLog, Provider};
use crate::store::{Cursor, EventsQuery};
use crate::{Descriptor, Result, forbidden, permissions};

/// Handle a query message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    query.authorize(owner, provider).await?;

    // FIXME: use pagination cursor
    let query = EventsQuery::from(query);
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
        let Some(grant_id) = &authzn.payload()?.permission_grant_id else {
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
