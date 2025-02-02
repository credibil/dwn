//! # Protocols Query
//!
//! The protocols query endpoint handles `ProtocolsQuery` messages — requests
//! to query the [`MessageStore`] for protocols configured for the DWN.

use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::endpoint::{Message, Reply, Status};
use crate::protocols::{Configure, ProtocolsFilter};
use crate::provider::{MessageStore, Provider};
use crate::store::{self, Cursor, ProtocolsQueryBuilder};
use crate::utils::cid;
use crate::{Descriptor, Result, permissions, utils};

// Access level for query.
#[derive(PartialEq, PartialOrd)]
enum Access {
    Published,
    Unpublished,
}

/// Handle — or process — a [`Query`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs querying the [`MessageStore`].
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
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
            code: 200,
            detail: Some("OK".to_string()),
        },
        body: Some(QueryReply {
            entries: Some(entries),
            cursor,
        }),
    })
}

/// The [`Query`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
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
        self.authorization.as_ref()
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

/// [`QueryReply`] is returned by the handler in the [`Reply`] `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryReply {
    /// [`Configure`] entries matching the query.
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
    let mut builder = store::ProtocolsQueryBuilder::new();
    if let Some(protocol) = protocol {
        builder = builder.protocol(&protocol);
    }

    // execute query
    let (messages, _) = store.query(owner, &builder.build()).await?;
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
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, self.descriptor(), store).await?;

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

/// The [`Query`] message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<ProtocolsFilter>,
}
