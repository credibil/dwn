//! # Protocols Query
//!
//! The protocols query endpoint handles `ProtocolsQuery` messages — requests
//! to query the [`MessageStore`] for protocols configured for the DWN.

use http::StatusCode;

use crate::endpoint::{Reply, ReplyBody, Status};
use crate::handlers::verify_grant;
use crate::interfaces::protocols::{Access, Configure, Query, QueryReply};
use crate::provider::{MessageStore, Provider};
use crate::store::ProtocolsQueryBuilder;
use crate::{Result, utils};

/// Handle — or process — a [`Query`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs querying the [`MessageStore`].
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply> {
    // validate query
    if let Some(filter) = &query.descriptor.filter {
        utils::uri::validate(&filter.protocol)?;
    }

    // build actual query
    let mut builder = ProtocolsQueryBuilder::new();
    if let Some(filter) = &query.descriptor.filter {
        builder = builder.protocol(&filter.protocol);
    }

    // unauthorized queries can only query for published protocols
    if query.authorize(owner, provider).await? == Access::Published {
        builder = builder.published(true);
    }

    let (records, cursor) = MessageStore::query(provider, owner, &builder.build()).await?;

    // unpack messages
    let mut entries = vec![];
    for record in records {
        entries.push(Configure::try_from(record)?);
    }

    Ok(Reply {
        status: Status {
            code: StatusCode::OK,
            detail: None,
        },
        body: Some(ReplyBody::ProtocolsQuery(QueryReply {
            entries: Some(entries),
            cursor,
        })),
    })
}

impl Query {
    /// Check message has sufficient privileges.
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<Access> {
        let Some(authzn) = &self.authorization else {
            return Ok(Access::Published);
        };

        if authzn.author()? == owner {
            return Ok(Access::Unpublished);
        }

        // does the message have a permission grant?
        let Some(grant_id) = &authzn.payload()?.permission_grant_id else {
            return Ok(Access::Published);
        };

        // verify permission grant
        let grant = verify_grant::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, &self.descriptor.base, store).await?;

        // if set, query and grant protocols need to match
        let Some(protocol) = grant.data.scope.protocol() else {
            return Ok(Access::Unpublished);
        };
        // has a grant but no filter: published protocols only
        let Some(filter) = &self.descriptor.filter else {
            return Ok(Access::Published);
        };
        // filter protocol must match grant protocol
        if protocol != filter.protocol {
            return Ok(Access::Published);
        }

        Ok(Access::Unpublished)
    }
}
