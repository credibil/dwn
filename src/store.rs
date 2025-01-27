//! # Store

pub mod block;
pub mod index;

use std::collections::HashMap;
use std::ops::Deref;

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::endpoint::Message;
pub use crate::messages::MessagesFilter;
use crate::protocols::Configure;
pub use crate::protocols::ProtocolsFilter;
use crate::records::{self, Delete, Write};
pub use crate::records::{RecordsFilter, Sort, TagFilter};
use crate::{DateRange, Descriptor, Method, Result, messages, protocols};
pub use crate::{Interface, Lower, Range, Upper, unexpected};

/// Entry wraps each message with a unifying type used for all stored messages
/// (`RecordsWrite`, `RecordsDelete`, and `ProtocolsConfigure`).
///
/// The `Entry` type simplifies storage and retrieval aas well as providing a
/// a vehicle for persisting addtional data alongside the message (using the
/// `indexes` property).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Entry {
    /// The message type to store.
    #[serde(flatten)]
    pub message: EntryType,

    /// Indexable fields derived from the associated message object.
    // #[serde(skip)]
    pub indexes: HashMap<String, String>,
}

impl Entry {
    /// The message's CID.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn cid(&self) -> Result<String> {
        match self.message {
            EntryType::Write(ref write) => write.cid(),
            EntryType::Delete(ref delete) => delete.cid(),
            EntryType::Configure(ref configure) => configure.cid(),
        }
    }

    /// The message's CID.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor {
        match self.message {
            EntryType::Write(ref write) => write.descriptor(),
            EntryType::Delete(ref delete) => delete.descriptor(),
            EntryType::Configure(ref configure) => configure.descriptor(),
        }
    }

    /// Return the `RecordsWrite` message, if set.
    #[must_use]
    pub const fn as_write(&self) -> Option<&records::Write> {
        match &self.message {
            EntryType::Write(write) => Some(write),
            _ => None,
        }
    }

    /// Return the `RecordsDelete` message, if set.
    #[must_use]
    pub const fn as_delete(&self) -> Option<&records::Delete> {
        match &self.message {
            EntryType::Delete(delete) => Some(delete),
            _ => None,
        }
    }

    /// Return the `ProtocolsConfigure` message, if set.
    #[must_use]
    pub const fn as_configure(&self) -> Option<&protocols::Configure> {
        match &self.message {
            EntryType::Configure(configure) => Some(configure),
            _ => None,
        }
    }
}

impl Deref for Entry {
    type Target = EntryType;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

// LATER: perhaps should be TryFrom?
impl From<&Write> for Entry {
    fn from(write: &Write) -> Self {
        Self {
            message: EntryType::Write(write.clone()),
            indexes: write.indexes(),
        }
    }
}

impl From<&Delete> for Entry {
    fn from(delete: &Delete) -> Self {
        Self {
            message: EntryType::Delete(delete.clone()),
            indexes: delete.indexes(),
        }
    }
}

impl From<&Configure> for Entry {
    fn from(configure: &Configure) -> Self {
        Self {
            message: EntryType::Configure(configure.clone()),
            indexes: configure.indexes(),
        }
    }
}

/// `EntryType` holds the read message payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum EntryType {
    /// `RecordsWrite` message.
    Write(records::Write),

    /// `RecordsDelete` message.
    Delete(records::Delete),

    /// `ProtocolsConfigure` message.
    Configure(protocols::Configure),
}

impl Default for EntryType {
    fn default() -> Self {
        Self::Write(records::Write::default())
    }
}

/// `Query` wraps supported queries.
#[derive(Clone, Debug)]
pub enum Query {
    /// Records query.
    Records(RecordsQuery),

    /// Protocols query.
    Protocols(ProtocolsQuery),

    /// Messages query.
    Messages(EventsQuery),

    /// Granted query.
    Granted(GrantedQuery),
}

impl From<ProtocolsQuery> for Query {
    fn from(query: ProtocolsQuery) -> Self {
        Self::Protocols(query)
    }
}

impl From<RecordsQuery> for Query {
    fn from(query: RecordsQuery) -> Self {
        Self::Records(query)
    }
}

impl From<GrantedQuery> for Query {
    fn from(query: GrantedQuery) -> Self {
        Self::Granted(query)
    }
}

impl From<EventsQuery> for Query {
    fn from(query: EventsQuery) -> Self {
        Self::Messages(query)
    }
}

/// A set of field/value matchers that must be 'AND-ed' together for a
/// successful match.
#[derive(Clone, Debug, Default)]
pub struct MatchSet {
    /// The set of matchers.
    pub inner: Vec<Matcher>,

    /// Index to use for the query.
    pub index: Option<(String, String)>,
}

// impl Iterator for &MatchSet {
//     type Item = Matcher;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.set.pop()
//     }
// }

// impl Deref for MatchSet {
//     type Target = Vec<Matcher>;

//     fn deref(&self) -> &Self::Target {
//         &self.inner
//     }
// }

/// A field/value matcher for use in finding matching indexed values.
#[derive(Clone, Debug)]
pub struct Matcher {
    /// The name of the field this matcher applies to.
    pub field: String,

    /// The value and strategy to use for a successful match.
    pub value: MatchOn,
}

impl Matcher {
    /// Check if the field value matches the filter value.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn is_match(&self, value: &str) -> Result<bool> {
        let matched = match &self.value {
            MatchOn::Equal(filter_val) => value == filter_val,
            MatchOn::StartsWith(filter_val) => value.starts_with(filter_val),
            MatchOn::OneOf(values) => values.contains(&value.to_string()),
            MatchOn::Range(range) => {
                let int_val: usize =
                    value.parse().map_err(|e| unexpected!("issue parsing usize: {e}"))?;
                range.contains(&int_val)
            }
            MatchOn::DateRange(range) => {
                let date_val = DateTime::parse_from_rfc3339(value)
                    .map_err(|e| unexpected!("issue parsing date: {e}"))?;
                range.contains(&date_val.into())
            }
        };
        Ok(matched)
    }
}

/// Filter value.
#[derive(Clone, Debug)]
pub enum MatchOn {
    /// Match must be equal.
    Equal(String),

    /// Match must start with the specified value.
    StartsWith(String),

    /// Match on one of the items specified.
    OneOf(Vec<String>),

    /// Match must be in the specified range.
    Range(Range<usize>),

    /// Match must be in the specified date range.
    DateRange(DateRange),
}

/// `ProtocolsQuery` use a builder to simplify the process of creating
/// `MessageStore` queries.
#[derive(Clone, Debug, Default)]
pub struct ProtocolsQuery {
    /// Filter records by `protocol`.
    pub protocol: Option<String>,

    /// Filter records by by their `published` status.
    pub published: Option<bool>,
}

impl From<protocols::Query> for ProtocolsQuery {
    fn from(query: protocols::Query) -> Self {
        let mut pq = Self::default();
        if let Some(filter) = query.descriptor.filter {
            pq.protocol = Some(filter.protocol);
        }
        pq
    }
}

/// `RecordsQuery` use a builder to simplify the process of creating
/// `RecordWrite` and `RecordsDelete` queries against the `MessageStore`.
#[derive(Clone, Debug, Default)]
pub struct RecordsQuery {
    // /// Filter records using one or more filters OR'ed together.
    // pub filters: Vec<RecordsFilter>,
    /// One or more sets of events to match.
    pub match_sets: Vec<MatchSet>,

    /// Sort options.
    pub sort: Sort,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl RecordsQuery {
    /// Determine whether the query can be expressed in a concise form.
    #[must_use]
    pub fn is_concise(&self) -> bool {
        for ms in &self.match_sets {
            if ms.index.is_none() {
                return false;
            }
        }
        true
    }
}

impl From<records::Query> for RecordsQuery {
    fn from(query: records::Query) -> Self {
        let mut match_set = MatchSet {
            inner: vec![
                Matcher {
                    field: "method".to_string(),
                    value: MatchOn::Equal(Method::Write.to_string()),
                },
                Matcher {
                    field: "archived".to_string(),
                    value: MatchOn::Equal(false.to_string()),
                },
            ],
            ..MatchSet::default()
        };

        // add filter to match_set
        let ms = MatchSet::from(&query.descriptor.filter);
        match_set.inner.extend(ms.inner);
        match_set.index = ms.index;

        Self {
            match_sets: vec![match_set],
            sort: query.descriptor.date_sort.unwrap_or_default(),
            pagination: query.descriptor.pagination,
        }
    }
}

impl From<records::Read> for RecordsQuery {
    fn from(read: records::Read) -> Self {
        let mut match_set = MatchSet {
            inner: vec![Matcher {
                field: "archived".to_string(),
                value: MatchOn::Equal(false.to_string()),
            }],
            ..MatchSet::default()
        };

        let ms = MatchSet::from(&read.descriptor.filter);
        match_set.inner.extend(ms.inner);
        match_set.index = ms.index;

        Self {
            match_sets: vec![match_set],
            ..Self::default()
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
                field: "record_id".to_string(),
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

    /// Build the `RecordsQuery`.
    #[must_use]
    pub fn build(self) -> RecordsQuery {
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
                    field: "archived".to_string(),
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

        RecordsQuery {
            match_sets,
            sort: self.sort,
            pagination: self.pagination,
        }
    }
}

/// `EventsQuery` for `EventLog` queries.
#[derive(Clone, Debug, Default)]
pub struct EventsQuery {
    /// One or more sets of events to match.
    pub match_sets: Vec<MatchSet>,

    /// Sort options.
    pub sort: Sort,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl From<messages::Query> for EventsQuery {
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
            if let Some(protocol) = &filter.protocol {
                match_set.inner.push(Matcher {
                    field: "protocol".to_string(),
                    value: MatchOn::Equal(protocol.to_string()),
                });
                match_set.inner.push(Matcher {
                    field: "tag.protocol".to_string(),
                    value: MatchOn::Equal(protocol.to_string()),
                });
            }
            if let Some(message_timestamp) = &filter.message_timestamp {
                match_set.inner.push(Matcher {
                    field: "messageTimestamp".to_string(),
                    value: MatchOn::DateRange(message_timestamp.clone()),
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

/// `GrantedQuery` is used to find grant-authorized `RecordsWrite` messages.
#[derive(Clone, Debug)]
pub struct GrantedQuery {
    /// Select messages authorized by this grant ID.
    pub permission_grant_id: String,

    /// Select messages created within this date range.
    pub date_created: DateRange,
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Cursor created form the previous page of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

impl Pagination {
    /// Create a new `Pagination` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limit: None,
            cursor: None,
            // offinner: None,
        }
    }

    /// Set the limit.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the cursor.
    #[must_use]
    pub fn cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

/// Pagination cursor containing data from the last entry returned in the
/// previous page of results.
///
/// Message CID ensures result cursor compatibility irrespective of DWN
/// implementation. Meaning querying with the same cursor yields identical
/// results regardless of DWN queried.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    /// Message CID from the last entry in the previous page of results.
    pub message_cid: String,

    /// The value (from sort field) of the last entry in the previous page of
    /// results.
    pub value: String,
}
