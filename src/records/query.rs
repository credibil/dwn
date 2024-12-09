//! # Query
//!
//! `Query` is a message type used to query a record in the web node.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::permissions::{Grant, Protocol};
use crate::provider::{MessageStore, Provider, Signer};
use crate::records::{DelegatedGrant, RecordsFilter, Write};
use crate::store::{Cursor, Pagination, RecordsQuery, Sort};
use crate::{Descriptor, Interface, Method, Quota, Result, forbidden, unauthorized, unexpected};

/// Process `Query` message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    let mut filter = query.descriptor.filter.clone();

    // authorize messages querying for private records
    if !filter.published.unwrap_or_default() {
        query.authorize(owner, provider).await?;
        query.validate()?;

        let Some(authzn) = &query.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;

        // non-owner queries
        if author != owner {
            // when query.author is in filter.author or filter.author is empty/None,
            filter.author = Some(Quota::One(author.clone()));

            // when query.author is in filter.recipient || filter.recipient is
            // empty/None, set filter.recipient = query.author
            filter.recipient = Some(Quota::One(author));

            // when filter.protocol_role ??
        }
    }

    // get the latest active `RecordsWrite` records
    let rq = RecordsQuery::from(query);
    let (records, _) = MessageStore::query(provider, owner, &rq.into()).await?;

    // short-circuit when no records found
    if records.is_empty() {
        return Ok(Reply {
            status: Status {
                code: StatusCode::OK.as_u16(),
                detail: None,
            },
            body: None,
        });
    }

    // build reply
    let mut entries = vec![];
    for record in records {
        let write: Write = record.try_into()?;

        let initial_write = if write.is_initial()? {
            let query = RecordsQuery::new().record_id(&write.record_id).include_archived(true);
            let (records, _) = MessageStore::query(provider, owner, &query.into()).await?;
            let mut initial_write: Write = (&records[0]).try_into()?;
            initial_write.encoded_data = None;
            Some(initial_write)
        } else {
            None
        };

        entries.push(QueryReplyEntry { write, initial_write });
    }

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(QueryReply {
            entries: Some(entries),
            cursor: None,
        }),
    })
}

/// Records Query payload
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct QueryReply {
    /// Query reply entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<QueryReplyEntry>>,

    /// Pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Query reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryReplyEntry {
    /// The `RecordsWrite` message of the record if record exists.
    #[serde(flatten)]
    pub write: Write,

    /// The initial write of the record if the returned `RecordsWrite` message
    /// itself is not the initial write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_write: Option<Write>,
}

impl Query {
    async fn authorize(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };

        // authenticate the message
        if let Err(e) = authzn.authenticate(provider.clone()).await {
            return Err(unauthorized!("failed to authenticate: {e}"));
        }

        // verify grant
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant: Grant = delegated_grant.try_into()?;
            grant.permit_query(&authzn.author()?, &authzn.signer()?, self, provider).await?;
        }

        // verify protocol when request invokes a protocol role
        if let Some(protocol) = &authzn.jws_payload()?.protocol_role {
            let protocol =
                Protocol::new(protocol).context_id(self.descriptor.filter.context_id.as_ref());
            return protocol.permit_query(owner, self, provider).await;
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        validate_sort(self.descriptor.date_sort.as_ref(), &self.descriptor.filter)?;

        Ok(())
    }
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    pub filter: RecordsFilter,

    /// Specifies how dates should be sorted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_sort: Option<Sort>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Pagination>,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct QueryBuilder {
    // pub struct QueryBuilder<'a, S: Signer> {
    message_timestamp: DateTime<Utc>,
    filter: Option<RecordsFilter>,
    date_sort: Option<Sort>,
    pagination: Option<Pagination>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    // signer: Option<&'a S>,
    // attesters: Option<Vec<&'a S>>,
}

impl QueryBuilder {
    // impl<'a, S: Signer> QueryBuilder<'a, S> {

    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn filter(mut self, filter: RecordsFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Determines which date to use when sorting query results.
    #[must_use]
    pub const fn date_sort(mut self, date_sort: Sort) -> Self {
        self.date_sort = Some(date_sort);
        self
    }

    /// Sets the limit (size) and offset of the resultset pagination cursor.
    #[must_use]
    pub fn pagination(mut self, pagination: Pagination) -> Self {
        self.pagination = Some(pagination);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify a protocol role for the record.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// The delegated grant used with this record.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Build the write message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: Option<&impl Signer>) -> Result<Query> {
        let Some(filter) = self.filter else {
            return Err(unexpected!("missing filter"));
        };

        validate_sort(self.date_sort.as_ref(), &filter)?;

        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filter: filter.normalize()?,
            date_sort: self.date_sort,
            pagination: self.pagination,
        };

        // let authorization = if self.authorize.unwrap_or(true) {
        let authorization = if let Some(signer) = signer {
            let mut auth_builder =
                AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
            if let Some(id) = self.permission_grant_id {
                auth_builder = auth_builder.permission_grant_id(id);
            }
            if let Some(role) = self.protocol_role {
                auth_builder = auth_builder.protocol_role(role);
            }
            if let Some(delegated_grant) = self.delegated_grant {
                auth_builder = auth_builder.delegated_grant(delegated_grant);
            }
            Some(auth_builder.build(signer).await?)
        } else {
            None
        };

        Ok(Query {
            descriptor,
            authorization,
        })
    }
}

fn validate_sort(sort: Option<&Sort>, filter: &RecordsFilter) -> Result<()> {
    let Some(sort) = sort else {
        return Ok(());
    };

    if !filter.published.unwrap_or_default()
        && (sort == &Sort::PublishedAscending || sort == &Sort::PublishedDescending)
    {
        return Err(unexpected!(
            "cannot sort by `date_published` when querying for unpublished records"
        ));
    }

    Ok(())
}
