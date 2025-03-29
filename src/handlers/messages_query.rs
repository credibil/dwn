//! # Messages Query
//!
//! The messages query endpoint handles `MessagesQuery` messages — requests
//! to query the [`EventLog`] for matching persisted messages (of any type).

use http::StatusCode;

use crate::endpoint::{Reply, ReplyBody, Status};
use crate::handlers::verify_grant;
use crate::interfaces::messages::{Query, QueryReply};
use crate::provider::{EventLog, Provider};
use crate::{Result, forbidden, store};

/// Handle — or process — a [`Query`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs querying the [`EventLog`].
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<ReplyBody>> {
    query.authorize(owner, provider).await?;

    let query = store::Query::from(query);
    let (events, cursor) = EventLog::query(provider, owner, &query).await?;

    let events = events.iter().map(|e| e.cid().unwrap_or_default()).collect::<Vec<String>>();
    let entries = if events.is_empty() { None } else { Some(events) };

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(ReplyBody::MessagesQuery(QueryReply { entries, cursor })),
    })
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
        let grant = verify_grant::fetch_grant(owner, grant_id, provider).await?;
        grant.verify(owner, &authzn.signer()?, &self.descriptor.base, provider).await?;

        // verify filter protocol
        if grant.data.scope.protocol().is_none() {
            return Ok(());
        }

        let protocol = grant.data.scope.protocol();
        for filter in &self.descriptor.filters {
            if filter.protocol.as_deref() != protocol {
                return Err(forbidden!("filter and grant protocols do not match"));
            }
        }

        Ok(())
    }
}
