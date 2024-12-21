//! # Query
//!
//! `Query` is a message type used to query a record in the web node.

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
use crate::{Descriptor, Interface, Method, Result, forbidden, unauthorized, unexpected, utils};

/// Process `Query` message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Reply<QueryReply>> {
    query.validate()?;

    let store_query = if query.only_published() {
        // correct filter when querying soley for published records
        let mut query = query;
        query.descriptor.filter.published = Some(true);
        RecordsQuery::from(query)
    } else {
        query.authorize(owner, provider).await?;
        let Some(authzn) = &query.authorization else {
            return Err(forbidden!("missing authorization"));
        };

        if authzn.author()? == owner {
            RecordsQuery::from(query)
        } else {
            query.into_non_owner()?
        }
    };

    // fetch records matching query criteria
    let (records, cursor) =
        MessageStore::paginated_query(provider, owner, &store_query.into()).await?;

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

        // short-circuit when the record is an initial write
        if write.is_initial()? {
            entries.push(QueryReplyEntry {
                write,
                initial_write: None,
            });
            continue;
        }

        // get the initial write for the returned `RecordsWrite`
        let query = RecordsQuery::new()
            .add_filter(RecordsFilter::new().record_id(&write.record_id))
            .include_archived(true);
        let records = MessageStore::query(provider, owner, &query.into()).await?;
        let mut initial_write: Write = (&records[0]).try_into()?;
        initial_write.encoded_data = None;

        entries.push(QueryReplyEntry {
            write,
            initial_write: Some(initial_write),
        });
    }

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(QueryReply {
            entries: Some(entries),
            cursor,
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
        if authzn.jws_payload()?.protocol_role.is_some() {
            let Some(protocol) = &self.descriptor.filter.protocol else {
                return Err(unexpected!("missing protocol"));
            };
            let Some(protocol_path) = &self.descriptor.filter.protocol_path else {
                return Err(unexpected!("missing `protocol_path`"));
            };
            if protocol_path.contains('/') && self.descriptor.filter.context_id.is_none() {
                return Err(unexpected!("missing `context_id`"));
            }

            // verify protocol role is authorized
            let verifier =
                Protocol::new(protocol).context_id(self.descriptor.filter.context_id.as_ref());
            return verifier.permit_query(owner, self, provider).await;
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if let Some(protocol) = &self.descriptor.filter.protocol {
            utils::validate_url(protocol)?;
        }

        if let Some(schema) = &self.descriptor.filter.schema {
            utils::validate_url(schema)?;
        }

        let Some(published) = self.descriptor.filter.published else {
            return Ok(());
        };
        if published {
            return Ok(());
        }

        if self.descriptor.date_sort == Some(Sort::PublishedAscending)
            || self.descriptor.date_sort == Some(Sort::PublishedDescending)
        {
            return Err(unexpected!(
                "cannot sort by `date_published` when querying for unpublished records"
            ));
        }

        Ok(())
    }

    // when the `published` flag is unset and the query uses published-related
    // settings, set the `published` flag to true
    fn only_published(&self) -> bool {
        if let Some(published) = self.descriptor.filter.published {
            return published;
        }
        if self.descriptor.filter.date_published.is_some() {
            return true;
        }
        if self.descriptor.date_sort == Some(Sort::PublishedAscending)
            || self.descriptor.date_sort == Some(Sort::PublishedDescending)
        {
            return true;
        }
        if self.authorization.is_none() {
            return true;
        }
        false
    }

    // when requestor (message author) is not web node owner,
    // recreate filters to include query author as record author or recipient
    fn into_non_owner(self) -> Result<RecordsQuery> {
        let mut store_query = RecordsQuery::from(self.clone());

        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;

        store_query.filters = vec![];

        // New filter: copy query filter  and set `published` to true
        if self.descriptor.filter.published.is_none() {
            let filter = self.descriptor.filter.clone();
            store_query = store_query.add_filter(filter.published(true));
        }

        // New filter: copy query filter remove authors except `author`
        let mut filter = self.descriptor.filter.clone();
        filter.author = None;
        store_query = store_query.add_filter(filter.add_author(&author).published(false));

        // New filter: copy query filter and remove recipients except author
        let mut filter = self.descriptor.filter.clone();
        filter.recipient = None;
        store_query = store_query.add_filter(filter.add_recipient(&author).published(false));

        // New filter: author can query any record when authorized by a role
        if authzn.jws_payload()?.protocol_role.is_some() {
            let mut filter = self.descriptor.filter.clone();
            filter.published = Some(false);
            store_query = store_query.add_filter(filter.published(false));
        }

        Ok(store_query)
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
pub struct QueryBuilder<F, S> {
    message_timestamp: DateTime<Utc>,
    filter: F,
    date_sort: Option<Sort>,
    pagination: Option<Pagination>,
    protocol_role: Option<String>,
    permission_grant_id: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    signer: S,
}

pub struct Unsigned;
pub struct Signed<'a, S: Signer>(pub &'a S);

pub struct Unfiltered;
pub struct Filtered(RecordsFilter);

impl Default for QueryBuilder<Unfiltered, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBuilder<Unfiltered, Unsigned> {
    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            filter: Unfiltered,
            signer: Unsigned,
            date_sort: None,
            pagination: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
        }
    }

    /// Set the filter to use when querying.
    #[must_use]
    pub fn filter(self, filter: RecordsFilter) -> QueryBuilder<Filtered, Unsigned> {
        QueryBuilder {
            filter: Filtered(filter),
            message_timestamp: self.message_timestamp,
            date_sort: self.date_sort,
            pagination: self.pagination,
            signer: self.signer,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
        }
    }
}

/// State: Unsigned
impl<'a, F> QueryBuilder<F, Unsigned> {
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

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &'a S) -> QueryBuilder<F, Signed<'a, S>> {
        QueryBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            filter: self.filter,
            date_sort: self.date_sort,
            pagination: self.pagination,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
        }
    }
}

// Build without signing
impl QueryBuilder<Filtered, Unsigned> {
    /// Build the write message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn build(self) -> Result<Query> {
        // validate_sort(self.date_sort.as_ref(), &self.filter.0)?;

        Ok(Query {
            descriptor: QueryDescriptor {
                base: Descriptor {
                    interface: Interface::Records,
                    method: Method::Query,
                    message_timestamp: self.message_timestamp,
                },
                filter: self.filter.0.normalize()?,
                date_sort: self.date_sort,
                pagination: self.pagination,
            },
            authorization: None,
        })
    }
}

// Build includes signing
impl<S: Signer> QueryBuilder<Filtered, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self) -> Result<Query> {
        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0.normalize()?,
            date_sort: self.date_sort,
            pagination: self.pagination,
        };

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
        let authorization = Some(auth_builder.build(self.signer.0).await?);

        Ok(Query {
            descriptor,
            authorization,
        })
    }
}
