//! # Records Query
//!
//! The documents query endpoint handles `RecordsQuery` messages — requests
//! to query the [`MessageStore`] for matching [`Write`] (and possibly
//! [`Delete`]) messages.

use credibil_core::api::{Body, Handler, Request, Response};

use crate::authorization::Authorization;
use crate::error::{bad_request, forbidden};
use crate::grants::Grant;
use crate::handlers::{BodyExt, Error, Result, verify_protocol};
use crate::interfaces::Descriptor;
use crate::interfaces::records::{Query, QueryReply, QueryReplyEntry, RecordsFilter, Sort, Write};
use crate::provider::{MessageStore, Provider};
use crate::store::{self, RecordsQueryBuilder};
use crate::utils;

/// Handle — or process — a [`Query`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs querying the [`MessageStore`].
pub async fn handle(owner: &str, provider: &impl Provider, query: Query) -> Result<QueryReply> {
    query.validate()?;

    let store_query = if query.only_published() {
        // correct filter when querying soley for published documents
        let mut query = query;
        query.descriptor.filter.published = Some(true);
        store::Query::from(query)
    } else {
        query.authorize(owner, provider).await?;
        let Some(authzn) = &query.authorization else {
            return Err(forbidden!("missing authorization"));
        };

        if authzn.author()? == owner {
            store::Query::from(query)
        } else {
            query.into_non_owner()?
        }
    };

    // fetch documents matching query criteria
    let (documents, cursor) = MessageStore::query(provider, owner, &store_query).await?;

    // short-circuit when no documents found
    if documents.is_empty() {
        return Ok(QueryReply::default());
    }

    // build reply
    let mut entries = vec![];
    for document in documents {
        let write: Write = document.try_into()?;

        // short-circuit when the record is an initial write
        if write.is_initial()? {
            entries.push(QueryReplyEntry { write, initial_write: None });
            continue;
        }

        // get the initial write for the returned `RecordsWrite`
        let query = RecordsQueryBuilder::new()
            .add_filter(RecordsFilter::new().record_id(&write.record_id))
            .include_archived(true)
            .build();
        let (results, _) = MessageStore::query(provider, owner, &query).await?;
        let mut initial_write: Write = (&results[0]).try_into()?;
        initial_write.encoded_data = None;

        entries.push(QueryReplyEntry { write, initial_write: Some(initial_write) });
    }

    Ok(QueryReply { entries: Some(entries), cursor })
}

impl<P: Provider> Handler<QueryReply, P> for Request<Query> {
    type Error = Error;

    async fn handle(self, owner: &str, provider: &P) -> Result<Response<QueryReply>> {
        BodyExt::validate(&self.body, provider).await?;
        Ok(handle(owner, provider, self.body).await?.into())
    }
}

impl Body for Query {}
impl BodyExt for Query {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }
}

impl Query {
    async fn authorize(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };

        // verify grant
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant: Grant = delegated_grant.try_into()?;
            grant.permit_query(&authzn.author()?, &authzn.signer()?, self, provider).await?;
        }

        // verify protocol when request invokes a protocol role
        if authzn.payload()?.protocol_role.is_some() {
            let Some(protocol) = &self.descriptor.filter.protocol else {
                return Err(bad_request!("missing protocol"));
            };
            let Some(protocol_path) = &self.descriptor.filter.protocol_path else {
                return Err(bad_request!("missing `protocol_path`"));
            };
            if protocol_path.contains('/') && self.descriptor.filter.context_id.is_none() {
                return Err(bad_request!("missing `context_id`"));
            }

            // verify protocol role is authorized
            let verifier = verify_protocol::Authorizer::new(protocol)
                .context_id(self.descriptor.filter.context_id.as_ref());
            return verifier.permit_query(owner, self, provider).await;
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if let Some(protocol) = &self.descriptor.filter.protocol {
            utils::uri::validate(protocol)?;
        }

        if let Some(schema) = &self.descriptor.filter.schema {
            utils::uri::validate(schema)?;
        }

        let Some(published) = self.descriptor.filter.published else {
            return Ok(());
        };
        if published {
            return Ok(());
        }

        if self.descriptor.date_sort == Some(Sort::PublishedAsc)
            || self.descriptor.date_sort == Some(Sort::PublishedDesc)
        {
            return Err(bad_request!(
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
        if self.descriptor.date_sort == Some(Sort::PublishedAsc)
            || self.descriptor.date_sort == Some(Sort::PublishedDesc)
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
    fn into_non_owner(self) -> Result<store::Query> {
        // let mut store_query = RecordsQueryBuilder::from(self.clone());
        let mut store_query = RecordsQueryBuilder::new();
        if let Some(date_sort) = self.descriptor.date_sort {
            store_query = store_query.sort(date_sort);
        }
        if let Some(pagination) = self.descriptor.pagination {
            store_query = store_query.pagination(pagination);
        }

        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;

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
        if authzn.payload()?.protocol_role.is_some() {
            let mut filter = self.descriptor.filter.clone();
            filter.published = Some(false);
            store_query = store_query.add_filter(filter.published(false));
        }

        Ok(store_query.build())
    }
}
