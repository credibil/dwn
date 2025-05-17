//! # Messages Query
//!
//! The messages query endpoint handles `MessagesQuery` messages — requests
//! to query the [`EventLog`] for matching persisted messages (of any type).

use crate::authorization::Authorization;
use crate::error::forbidden;
use crate::handlers::{Body, Error, Handler, Reply, Request, Result, verify_grant};
use crate::interfaces::Descriptor;
use crate::interfaces::messages::{Query, QueryReply};
use crate::provider::{EventLog, Provider};
use crate::store;

/// Handle — or process — a [`Query`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs querying the [`EventLog`].
async fn handle(owner: &str, provider: &impl Provider, query: Query) -> Result<QueryReply> {
    query.authorize(owner, provider).await?;

    let query = store::Query::from(query);
    let (events, cursor) = EventLog::query(provider, owner, &query).await?;

    let events = events.iter().map(|e| e.cid().unwrap_or_default()).collect::<Vec<String>>();
    let entries = if events.is_empty() { None } else { Some(events) };

    Ok(QueryReply { entries, cursor })
}

impl<P: Provider> Handler<P> for Request<Query> {
    type Error = Error;
    type Provider = P;
    type Reply = QueryReply;

    async fn handle(
        self, verifier: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Reply<Self::Reply>>, Self::Error> {
        handle(verifier, provider, self.body).await
    }
}

impl Body for Query {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
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
