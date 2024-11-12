//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use super::Filter;
use crate::auth::Authorization;
use crate::messages::Event;
use crate::permissions::{self, ScopeType};
use crate::provider::{EventLog, MessageStore, Provider};
use crate::service::Context;
use crate::{cid, unexpected, Cursor, Descriptor, Error, Message, Result, Status};

/// Handle a query message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(owner: &str, query: Query, provider: &impl Provider) -> Result<QueryReply> {
    let mut ctx = Context::new(owner);
    Message::validate(&query, &mut ctx, provider).await?;

    query.authorize(owner, provider).await?;

    // an empty array of filters means no filtering and all events are returned
    // const eventFilters = Messages.convertFilters(message.descriptor.filters);
    // const { events, cursor } = await this.eventLog.queryEvents(tenant, eventFilters, message.descriptor.cursor);

    let mut filter_sql = String::new();
    for filter in query.descriptor.filters {
        if !filter_sql.is_empty() {
            filter_sql.push_str("OR\n");
        }
        filter_sql.push_str("(");
        filter_sql.push_str(&filter.to_sql());
        filter_sql.push_str(")");
    }

    let sql = format!(
        "
        WHERE {filter_sql}
        AND latestBase = true
        ORDER BY descriptor.messageTimestamp ASC
        "
    );

    // TODO: use pagination cursor
    let (events, _) = EventLog::query(provider, owner, &sql).await?;
    if events.is_empty() {
        return Err(Error::NotFound("No matching records found".to_string()));
    }

    Ok(QueryReply {
        status: Status {
            code: 200,
            detail: None,
        },
        entries: Some(events),
        cursor: None,
    })
}

/// Messages Query payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

impl Message for Query {
    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }
}

impl Query {
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = authzn.author()?;

        if &author == owner {
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
            return Err(unexpected!("missing protocol scope",));
        };

        if protocol.is_none() {
            return Ok(());
        }

        for filter in &self.descriptor.filters {
            if &filter.protocol != protocol {
                return Err(unexpected!("filter protocol does not match scoped protocol"));
            }
        }

        Ok(())
    }
}
/// Messages Query reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct QueryReply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// The Query descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<Event>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<Filter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}
