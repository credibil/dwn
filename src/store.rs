//! # Store
//!
//! The `store` module provides utilities for storing and retrieving messages
//! and associated data.
//!
//! The two primary types exposed by this module are [`Storable`] and [`Query`].
//!
//! [`Storable`] wraps each message with a unifying type used to simplify storage
//! and retrieval as well as providing a vehicle for attaching addtional data
//! alongside the message (i.e. indexes).
//!
//! [`Query`] wraps store-specific query options for querying the underlying
//! store.

pub mod data;
pub(crate) mod event_log;
pub(crate) mod index;
pub(crate) mod message;
pub(crate) mod task;

use std::collections::HashMap;

use chrono::DateTime;

pub use self::data::MAX_ENCODED_SIZE;
use crate::interfaces::records::{self, RecordsFilter, Sort, TagFilter};
use crate::interfaces::{DateRange, Document, Pagination, Range, messages};
use crate::{Interface, Method, Result, bad};

/// The `Storable` trait is used to wrap each message with a unifying type used
/// for all stored messages (`RecordsWrite`, `RecordsDelete`, and `ProtocolsConfigure`).
pub trait Storable: Clone + Send + Sync {
    /// The message to store as a `Document`.
    ///
    /// # Errors
    ///
    /// The underlying CID computation is not infallible and may fail if the
    /// message cannot be serialized to CBOR.
    fn document(&self) -> Document;

    /// Indexes for this entry.
    fn indexes(&self) -> HashMap<String, String>;

    /// Adds a index item to the entry's indexes.
    fn add_index(&mut self, key: impl Into<String>, value: impl Into<String>);
}

/// The top-level query data structure used for both
/// [`crate::provider::MessageStore`] and [`crate::provider::EventLog`] 
/// queries.
///
/// The query is composed of one or more [`MatchSet`]s derived from filters
/// associated with the messagetype being queried. [`MatchSet`]s are 'OR-ed'
/// together to form the query.
///
/// Sorting and pagination options are also included although not always
/// used.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// One or more sets of events to match.
    pub(crate) match_sets: Vec<MatchSet>,

    /// Sort options.
    pub(crate) sort: Sort,

    /// Pagination options.
    pub(crate) pagination: Option<Pagination>,
}

impl Query {
    /// Determine whether the query can be expressed in a concise form.
    #[must_use]
    pub(crate) fn is_concise(&self) -> bool {
        if self.match_sets.is_empty() {
            return false;
        }

        for ms in &self.match_sets {
            let Some((_, value)) = &ms.index else {
                return false;
            };
            if value.is_empty() {
                return false;
            }
        }

        true
    }
}

impl From<records::Query> for Query {
    fn from(query: records::Query) -> Self {
        let mut match_set = MatchSet::from(&query.descriptor.filter);

        match_set.inner.insert(
            0,
            Matcher {
                field: "method".to_string(),
                value: MatchOn::Equal(Method::Write.to_string()),
            },
        );
        match_set.inner.push(Matcher {
            field: "initial".to_string(),
            value: MatchOn::Equal(false.to_string()),
        });

        Self {
            match_sets: vec![match_set],
            sort: query.descriptor.date_sort.unwrap_or_default(),
            pagination: query.descriptor.pagination,
        }
    }
}

impl From<records::Read> for Query {
    fn from(read: records::Read) -> Self {
        let mut match_set = MatchSet::from(&read.descriptor.filter);

        match_set.inner.push(Matcher {
            field: "initial".to_string(),
            value: MatchOn::Equal(false.to_string()),
        });

        Self {
            match_sets: vec![match_set],
            ..Self::default()
        }
    }
}

impl From<messages::Query> for Query {
    fn from(query: messages::Query) -> Self {
        let mut match_sets = vec![];

        for filter in &query.descriptor.filters {
            let mut match_set = MatchSet::default();

            if let Some(interface) = &filter.interface {
                match_set.inner.push(Matcher {
                    field: "interface".to_string(),
                    value: MatchOn::Equal(interface.to_string()),
                });
            }
            if let Some(method) = &filter.method {
                match_set.inner.push(Matcher {
                    field: "method".to_string(),
                    value: MatchOn::Equal(method.to_string()),
                });
            }
            if let Some(message_timestamp) = &filter.message_timestamp {
                match_set.inner.push(Matcher {
                    field: "messageTimestamp".to_string(),
                    value: MatchOn::DateRange(message_timestamp.clone()),
                });
            }

            // match on `protocol` OR `tag.protocol`
            if let Some(protocol) = &filter.protocol {
                // clone and create an OR `MatchSet`
                let mut ms = match_set.clone();
                ms.inner.push(Matcher {
                    field: "tag.protocol".to_string(),
                    value: MatchOn::Equal(protocol.to_string()),
                });
                match_sets.push(ms);

                match_set.inner.push(Matcher {
                    field: "protocol".to_string(),
                    value: MatchOn::Equal(protocol.to_string()),
                });
            }

            match_sets.push(match_set);
        }

        Self {
            match_sets,
            sort: Sort::TimestampAsc,
            pagination: None,
        }
    }
}

/// A `MatchSet` contains a set of [`Matcher`]s derived from the underlying
/// filter object. [`Matcher`]s are 'AND-ed' together for a successful match.
#[derive(Clone, Debug, Default)]
pub struct MatchSet {
    /// The set of matchers.
    pub inner: Vec<Matcher>,

    /// The index to use for the query.
    pub index: Option<(String, String)>,
}

/// A `Matcher` is used to match the `field`/`value` pair to a proovided index
/// value during the process of executing a query.
#[derive(Clone, Debug)]
pub struct Matcher {
    /// The name of the field this matcher applies to.
    pub(crate) field: String,

    /// The value and strategy to use for a successful match.
    pub(crate) value: MatchOn,
}

impl Matcher {
    /// Check if the field value matches the filter value.
    ///
    /// # Errors
    ///
    /// The `Matcher` may fail to parse the provided value to the correct type
    /// and will return an error in this case.
    pub(crate) fn is_match(&self, value: &str) -> Result<bool> {
        let matched = match &self.value {
            MatchOn::Equal(filter_val) => value == filter_val,
            MatchOn::StartsWith(filter_val) => value.starts_with(filter_val),
            MatchOn::OneOf(values) => values.contains(&value.to_string()),
            MatchOn::Range(range) => {
                let int_val = value
                    .parse()
                    .map_err(|e| bad!("issue converting match value to usize: {e}"))?;
                range.contains(&int_val)
            }
            MatchOn::DateRange(range) => {
                let date_val = DateTime::parse_from_rfc3339(value)
                    .map_err(|e| bad!("issue converting match value to date: {e}"))?;
                range.contains(&date_val.into())
            }
        };
        Ok(matched)
    }
}

/// The [`MatchOn`] enum is used to specify the matching strategy to be
/// employed by the `Matcher`.
#[derive(Clone, Debug)]
pub enum MatchOn {
    /// The match must be equal.
    Equal(String),

    /// The match must start with the specified value.
    StartsWith(String),

    /// The match must be with at least one of the items specified.
    OneOf(Vec<String>),

    /// The match must be in the specified range.
    Range(Range<usize>),

    /// The match must be in the specified date range.
    DateRange(DateRange),
}

impl From<&RecordsFilter> for MatchSet {
    #[allow(clippy::too_many_lines)]
    fn from(filter: &RecordsFilter) -> Self {
        let mut match_set = Self::default();

        if filter.is_concise() {
            match_set.index = filter.as_concise();
        }

        match_set.inner.push(Matcher {
            field: "interface".to_string(),
            value: MatchOn::Equal(Interface::Records.to_string()),
        });

        if let Some(record_id) = &filter.record_id {
            match_set.inner.push(Matcher {
                field: "recordId".to_string(),
                value: MatchOn::Equal(record_id.to_string()),
            });
        }
        if let Some(published) = &filter.published {
            match_set.inner.push(Matcher {
                field: "published".to_string(),
                value: MatchOn::Equal(published.to_string()),
            });
        }
        if let Some(author) = &filter.author {
            match_set.inner.push(Matcher {
                field: "author".to_string(),
                value: MatchOn::OneOf(author.to_vec()),
            });
        }
        if let Some(recipient) = &filter.recipient {
            match_set.inner.push(Matcher {
                field: "recipient".to_string(),
                value: MatchOn::OneOf(recipient.to_vec()),
            });
        }
        if let Some(protocol) = &filter.protocol {
            match_set.inner.push(Matcher {
                field: "protocol".to_string(),
                value: MatchOn::Equal(protocol.to_string()),
            });
        }
        if let Some(protocol_path) = &filter.protocol_path {
            match_set.inner.push(Matcher {
                field: "protocolPath".to_string(),
                value: MatchOn::Equal(protocol_path.to_string()),
            });
        }
        if let Some(context_id) = &filter.context_id {
            match_set.inner.push(Matcher {
                field: "contextId".to_string(),
                value: MatchOn::StartsWith(context_id.to_string()),
            });
        }
        if let Some(schema) = &filter.schema {
            match_set.inner.push(Matcher {
                field: "schema".to_string(),
                value: MatchOn::Equal(schema.to_string()),
            });
        }
        if let Some(parent_id) = &filter.parent_id {
            match_set.inner.push(Matcher {
                field: "parentId".to_string(),
                value: MatchOn::Equal(parent_id.to_string()),
            });
        }
        if let Some(data_format) = &filter.data_format {
            match_set.inner.push(Matcher {
                field: "dataFormat".to_string(),
                value: MatchOn::Equal(data_format.to_string()),
            });
        }
        if let Some(data_size) = &filter.data_size {
            match_set.inner.push(Matcher {
                field: "dataSize".to_string(),
                value: MatchOn::Range(data_size.clone()),
            });
        }
        if let Some(data_cid) = &filter.data_cid {
            match_set.inner.push(Matcher {
                field: "dataCid".to_string(),
                value: MatchOn::Equal(data_cid.to_string()),
            });
        }
        if let Some(date_created) = &filter.date_created {
            match_set.inner.push(Matcher {
                field: "dateCreated".to_string(),
                value: MatchOn::DateRange(date_created.clone()),
            });
        }
        if let Some(date_published) = &filter.date_published {
            match_set.inner.push(Matcher {
                field: "datePublished".to_string(),
                value: MatchOn::DateRange(date_published.clone()),
            });
        }
        if let Some(date_updated) = &filter.date_updated {
            match_set.inner.push(Matcher {
                field: "messageTimestamp".to_string(),
                value: MatchOn::DateRange(date_updated.clone()),
            });
        }
        if let Some(attester) = &filter.attester {
            match_set.inner.push(Matcher {
                field: "attester".to_string(),
                value: MatchOn::Equal(attester.to_string()),
            });
        }

        if let Some(tags) = &filter.tags {
            for (property, tag_filter) in tags {
                match tag_filter {
                    TagFilter::Equal(value) => {
                        if let Some(val_str) = value.as_str() {
                            match_set.inner.push(Matcher {
                                field: format!("tag.{property}"),
                                value: MatchOn::Equal(val_str.to_string()),
                            });
                        }
                    }
                    TagFilter::StartsWith(value) => {
                        match_set.inner.push(Matcher {
                            field: format!("tag.{property}"),
                            value: MatchOn::Equal(value.to_string()),
                        });
                    }
                    TagFilter::Range(range) => {
                        match_set.inner.push(Matcher {
                            field: format!("tag.{property}"),
                            value: MatchOn::Range(range.clone()),
                        });
                    }
                }
            }
        }

        match_set
    }
}

/// Build a protocols `Query` using a builder pattern.
#[derive(Clone, Debug, Default)]
pub struct ProtocolsQueryBuilder {
    protocol: Option<String>,
    published: Option<bool>,
}

impl ProtocolsQueryBuilder {
    /// Create a new `RecordsQueryBuilder` instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `Method` of the records to query for.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Include archived records in the query.
    #[must_use]
    pub const fn published(mut self, published: bool) -> Self {
        self.published = Some(published);
        self
    }

    /// Build the `RecordsQuery`.
    #[must_use]
    pub fn build(self) -> Query {
        let mut match_set = MatchSet {
            index: Some(("protocol".to_string(), String::new())),
            ..MatchSet::default()
        };

        match_set.inner.push(Matcher {
            field: "interface".to_string(),
            value: MatchOn::Equal(Interface::Protocols.to_string()),
        });

        if let Some(protocol) = &self.protocol {
            match_set.inner.push(Matcher {
                field: "protocol".to_string(),
                value: MatchOn::Equal(protocol.to_string()),
            });
        }
        if let Some(published) = &self.published {
            match_set.inner.push(Matcher {
                field: "published".to_string(),
                value: MatchOn::Equal(published.to_string()),
            });
        }

        Query {
            match_sets: vec![match_set],
            ..Query::default()
        }
    }
}

/// Build a `RecordsQuery` using a builder pattern.
#[derive(Clone, Debug, Default)]
pub struct RecordsQueryBuilder {
    filters: Vec<RecordsFilter>,
    method: Option<Method>,
    include_archived: bool,
    sort: Sort,
    pagination: Option<Pagination>,
}

impl RecordsQueryBuilder {
    /// Create a new `RecordsQueryBuilder` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            method: Some(Method::Write),
            ..Self::default()
        }
    }

    /// Add a filter to the query.
    #[must_use]
    pub fn add_filter(mut self, filter: RecordsFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Set the `Method` of the records to query for.
    #[must_use]
    pub const fn method(mut self, method: Option<Method>) -> Self {
        self.method = method;
        self
    }

    /// Include archived records in the query.
    #[must_use]
    pub const fn include_archived(mut self, include_archived: bool) -> Self {
        self.include_archived = include_archived;
        self
    }

    /// Set the sort order of the returned records.
    #[must_use]
    pub const fn sort(mut self, sort: Sort) -> Self {
        self.sort = sort;
        self
    }

    /// Set the pagination options.
    #[must_use]
    pub fn pagination(mut self, pagination: Pagination) -> Self {
        self.pagination = Some(pagination);
        self
    }

    /// Build the `Query`.
    #[must_use]
    pub fn build(self) -> Query {
        let mut match_sets = vec![];
        let mut is_concise = true;

        for filter in &self.filters {
            let mut match_set = MatchSet::default();

            if let Some(method) = &self.method {
                match_set.inner.push(Matcher {
                    field: "method".to_string(),
                    value: MatchOn::Equal(method.to_string()),
                });
            }
            if !self.include_archived {
                match_set.inner.push(Matcher {
                    field: "initial".to_string(),
                    value: MatchOn::Equal(false.to_string()),
                });
            }

            let ms = MatchSet::from(filter);
            match_set.inner.extend(ms.inner);
            match_set.index = ms.index;

            match_sets.push(match_set);

            if is_concise {
                is_concise = filter.is_concise();
            }
        }

        Query {
            match_sets,
            sort: self.sort,
            pagination: self.pagination,
        }
    }
}

/// Build a `GrantedQuery` using a builder pattern.
#[derive(Clone, Debug, Default)]
pub struct GrantedQueryBuilder {
    permission_grant_id: Option<String>,
    date_created: Option<DateRange>,
}

impl GrantedQueryBuilder {
    /// Create a new `RecordsQueryBuilder` instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `Method` of the records to query for.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Include archived records in the query.
    #[must_use]
    pub const fn date_created(mut self, date_created: DateRange) -> Self {
        self.date_created = Some(date_created);
        self
    }

    /// Build the `RecordsQuery`.
    #[must_use]
    pub fn build(self) -> Query {
        let mut match_set = MatchSet {
            index: Some(("protocol".to_string(), String::new())),
            ..MatchSet::default()
        };

        match_set.inner.push(Matcher {
            field: "interface".to_string(),
            value: MatchOn::Equal(Interface::Records.to_string()),
        });
        match_set.inner.push(Matcher {
            field: "method".to_string(),
            value: MatchOn::Equal(Method::Write.to_string()),
        });

        if let Some(permission_grant_id) = &self.permission_grant_id {
            match_set.inner.push(Matcher {
                field: "permissionGrantId".to_string(),
                value: MatchOn::Equal(permission_grant_id.to_string()),
            });
        }
        if let Some(date_created) = &self.date_created {
            match_set.inner.push(Matcher {
                field: "dateCreated".to_string(),
                value: MatchOn::DateRange(date_created.clone()),
            });
        }

        Query {
            match_sets: vec![match_set],
            ..Query::default()
        }
    }
}
