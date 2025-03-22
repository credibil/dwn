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

pub use datastore::data::MAX_ENCODED_SIZE;
pub use datastore::query::{
    self, Cursor, DateRange, Lower, MatchOn, MatchSet, Matcher, Pagination, Query, Range, Sort,
    Upper,
};
pub use datastore::store::{Document, Storable};

use crate::interfaces::messages;
use crate::interfaces::records::{self, RecordsFilter, TagFilter};
use crate::{Interface, Method};

impl From<records::Sort> for query::Sort {
    fn from(sort: records::Sort) -> Self {
        match sort {
            records::Sort::TimestampAsc => Self::Ascending("messageTimestamp".to_string()),
            records::Sort::TimestampDesc => Self::Descending("messageTimestamp".to_string()),
            records::Sort::PublishedAsc => Self::Ascending("datePublished".to_string()),
            records::Sort::PublishedDesc => Self::Descending("datePublished".to_string()),
            records::Sort::CreatedAsc => Self::Ascending("dateCreated".to_string()),
            records::Sort::CreatedDesc => Self::Descending("dateCreated".to_string()),
        }
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
            sort: query.descriptor.date_sort.unwrap_or_default().into(),
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
            sort: Sort::Ascending("messageTimestamp".to_string()),
            pagination: None,
        }
    }
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
    pub fn sort(mut self, sort: impl Into<Sort>) -> Self {
        self.sort = sort.into();
        self
    }

    /// Set the pagination options.
    #[must_use]
    pub fn pagination(mut self, pagination: impl Into<Pagination>) -> Self {
        self.pagination = Some(pagination.into());
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
    pub fn date_created(mut self, date_created: impl Into<DateRange>) -> Self {
        self.date_created = Some(date_created.into());
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

// impl<T: PartialEq> From<interfaces::Lower<T>> for Lower<T> {
//     fn from(lower: interfaces::Lower<T>) -> Self {
//         match lower {
//             interfaces::Lower::Inclusive(value) => Self::Inclusive(value),
//             interfaces::Lower::Exclusive(value) => Self::Exclusive(value),
//         }
//     }
// }

// impl<T: PartialEq> From<interfaces::Upper<T>> for Upper<T> {
//     fn from(lower: interfaces::Upper<T>) -> Self {
//         match lower {
//             interfaces::Upper::Inclusive(value) => Self::Inclusive(value),
//             interfaces::Upper::Exclusive(value) => Self::Exclusive(value),
//         }
//     }
// }

// impl<T: PartialEq> From<interfaces::Range<T>> for Range<T> {
//     fn from(range: interfaces::Range<T>) -> Self {
//         Self {
//             lower: range.lower.map(Into::into),
//             upper: range.upper.map(Into::into),
//         }
//     }
// }

// impl From<interfaces::DateRange> for DateRange {
//     fn from(date_range: interfaces::DateRange) -> Self {
//         Self {
//             lower: date_range.lower,
//             upper: date_range.upper,
//         }
//     }
// }

// impl From<interfaces::Pagination> for Pagination {
//     fn from(pagination: interfaces::Pagination) -> Self {
//         Self {
//             limit: pagination.limit,
//             cursor: pagination.cursor.map(Into::into),
//         }
//     }
// }

// impl From<interfaces::Cursor> for Cursor {
//     fn from(cursor: interfaces::Cursor) -> Self {
//         Self {
//             message_cid: cursor.message_cid,
//             value: cursor.value,
//         }
//     }
// }

// impl From<Cursor> for interfaces::Cursor {
//     fn from(cursor: Cursor) -> Self {
//         Self {
//             message_cid: cursor.message_cid,
//             value: cursor.value,
//         }
//     }
// }
