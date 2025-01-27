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
pub type MatchSet = Vec<Matcher>;

/// A field/value matcher for use in finding matching indexed values.
#[derive(Clone, Debug)]
pub struct Matcher {
    /// The name of the field this matcher applies to.
    pub field: &'static str,

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
#[derive(Clone, Debug)]
pub struct RecordsQuery {
    /// Filter records using one or more filters OR'ed together.
    pub filters: Vec<RecordsFilter>,

    /// Method of to use when querying records. Defaults to `RecordsWrite`, but
    /// can be set to `RecordsDelete` or None (for both).
    pub method: Option<Method>,

    /// Include records with the `archive` flag (i.e. include initial write for
    /// updated records).
    pub include_archived: bool,

    /// One or more sets of events to match.
    pub match_sets: Vec<MatchSet>,

    /// Sort options.
    pub sort: Sort,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl Default for RecordsQuery {
    fn default() -> Self {
        Self {
            filters: vec![],
            method: Some(Method::Write),
            include_archived: false,
            match_sets: vec![],
            sort: Sort::default(),
            pagination: None,
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
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            method: Some(Method::Write),
            ..Self::default()
        }
    }

    #[must_use]
    pub(crate) fn add_filter(mut self, filter: RecordsFilter) -> Self {
        self.filters.push(filter);
        self
    }

    #[must_use]
    pub(crate) const fn method(mut self, method: Option<Method>) -> Self {
        self.method = method;
        self
    }

    #[must_use]
    pub(crate) const fn include_archived(mut self, include_archived: bool) -> Self {
        self.include_archived = include_archived;
        self
    }

    #[must_use]
    pub(crate) const fn sort(mut self, sort: Sort) -> Self {
        self.sort = sort;
        self
    }

    #[must_use]
    pub(crate) fn pagination(mut self, pagination: Pagination) -> Self {
        self.pagination = Some(pagination);
        self
    }

    #[must_use]
    pub(crate) fn build(self) -> RecordsQuery {
        let mut match_sets = vec![];

        for filter in &self.filters {
            let mut match_set = vec![];

            if let Some(method) = &self.method {
                match_set.push(Matcher {
                    field: "method",
                    value: MatchOn::Equal(method.to_string()),
                });
            }
            if !self.include_archived {
                match_set.push(Matcher {
                    field: "archived",
                    value: MatchOn::Equal(false.to_string()),
                });
            }

            match_set.extend(MatchSet::from(filter));
            match_sets.push(match_set);
        }

        RecordsQuery {
            filters: self.filters,
            method: self.method,
            include_archived: self.include_archived,
            match_sets,
            sort: self.sort,
            pagination: self.pagination,
        }
    }
}

impl From<records::Query> for RecordsQuery {
    fn from(query: records::Query) -> Self {
        let mut match_set = vec![
            Matcher {
                field: "method",
                value: MatchOn::Equal(Method::Write.to_string()),
            },
            Matcher {
                field: "archived",
                value: MatchOn::Equal(false.to_string()),
            },
        ];
        match_set.extend(MatchSet::from(&query.descriptor.filter));

        Self {
            filters: vec![query.descriptor.filter],
            match_sets: vec![match_set],
            sort: query.descriptor.date_sort.unwrap_or_default(),
            pagination: query.descriptor.pagination,
            ..Self::default()
        }
    }
}

impl From<records::Read> for RecordsQuery {
    fn from(read: records::Read) -> Self {
        let mut match_set = vec![
            Matcher {
                field: "archived",
                value: MatchOn::Equal(false.to_string()),
            },
        ];
        match_set.extend(MatchSet::from(&read.descriptor.filter));

        Self {
            filters: vec![read.descriptor.filter],
            match_sets: vec![match_set],
            ..Self::default()
        }

        // Self {
        //     filters: vec![read.descriptor.filter],
        //     ..Self::default()
        // }
    }
}

impl From<&RecordsFilter> for MatchSet {
    fn from(filter: &RecordsFilter) -> Self {
        let mut match_set = MatchSet::default();

        match_set.push(Matcher {
            field: "interface",
            value: MatchOn::Equal(Interface::Records.to_string()),
        });

        if let Some(record_id) = &filter.record_id {
            match_set.push(Matcher {
                field: "record_id",
                value: MatchOn::Equal(record_id.to_string()),
            });
        }
        if let Some(published) = &filter.published {
            match_set.push(Matcher {
                field: "published",
                value: MatchOn::Equal(published.to_string()),
            });
        }
        if let Some(author) = &filter.author {
            match_set.push(Matcher {
                field: "author",
                value: MatchOn::OneOf(author.to_vec()),
            });
        }
        if let Some(recipient) = &filter.recipient {
            match_set.push(Matcher {
                field: "recipient",
                value: MatchOn::OneOf(recipient.to_vec()),
            });
        }
        if let Some(protocol) = &filter.protocol {
            match_set.push(Matcher {
                field: "protocol",
                value: MatchOn::Equal(protocol.to_string()),
            });
        }
        if let Some(protocol_path) = &filter.protocol_path {
            match_set.push(Matcher {
                field: "protocolPath",
                value: MatchOn::Equal(protocol_path.to_string()),
            });
        }
        if let Some(context_id) = &filter.context_id {
            match_set.push(Matcher {
                field: "contextId",
                value: MatchOn::StartsWith(context_id.to_string()),
            });
        }
        if let Some(schema) = &filter.schema {
            match_set.push(Matcher {
                field: "schema",
                value: MatchOn::Equal(schema.to_string()),
            });
        }
        if let Some(parent_id) = &filter.parent_id {
            match_set.push(Matcher {
                field: "parentId",
                value: MatchOn::Equal(parent_id.to_string()),
            });
        }
        if let Some(data_format) = &filter.data_format {
            match_set.push(Matcher {
                field: "dataFormat",
                value: MatchOn::Equal(data_format.to_string()),
            });
        }
        if let Some(data_size) = &filter.data_size {
            match_set.push(Matcher {
                field: "dataSize",
                value: MatchOn::Range(data_size.clone()),
            });
        }
        if let Some(data_cid) = &filter.data_cid {
            match_set.push(Matcher {
                field: "dataCid",
                value: MatchOn::Equal(data_cid.to_string()),
            });
        }
        if let Some(date_created) = &filter.date_created {
            match_set.push(Matcher {
                field: "dateCreated",
                value: MatchOn::DateRange(date_created.clone()),
            });
        }
        if let Some(date_published) = &filter.date_published {
            match_set.push(Matcher {
                field: "datePublished",
                value: MatchOn::DateRange(date_published.clone()),
            });
        }
        if let Some(date_updated) = &filter.date_updated {
            match_set.push(Matcher {
                field: "messageTimestamp",
                value: MatchOn::DateRange(date_updated.clone()),
            });
        }
        if let Some(attester) = &filter.attester {
            match_set.push(Matcher {
                field: "attester",
                value: MatchOn::Equal(attester.to_string()),
            });
        }

        // FIXME
        // FIXME: Add tag filters
        // FIXME
        // if let Some(tags) = &filter.tags {
        // for (property, tag_filter) in tags {
        // let tag_value = fields.get(&format!("tag.{property}")).unwrap_or(empty);
        // match tag_filter {
        //     TagFilter::StartsWith(value) => {
        //         if !tag_value.starts_with(value) {
        //             return Ok(false);
        //         }
        //     }
        //     TagFilter::Range(range) => {
        //         let tag_int = tag_value
        //             .parse::<usize>()
        //             .map_err(|e| unexpected!("issue parsing tag: {e}"))?;
        //         if !range.contains(&tag_int) {
        //             return Ok(false);
        //         }
        //     }
        //     TagFilter::Equal(value) => {
        //         if Some(tag_value.as_str()) != value.as_str() {
        //             return Ok(false);
        //         }
        //     }
        // }
        // }
        // }

        match_set
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
            let mut match_set = vec![];

            if let Some(interface) = &filter.interface {
                match_set.push(Matcher {
                    field: "interface",
                    value: MatchOn::Equal(interface.to_string()),
                });
            }
            if let Some(method) = &filter.method {
                match_set.push(Matcher {
                    field: "method",
                    value: MatchOn::Equal(method.to_string()),
                });
            }
            if let Some(protocol) = &filter.protocol {
                match_set.push(Matcher {
                    field: "protocol",
                    value: MatchOn::Equal(protocol.to_string()),
                });
                match_set.push(Matcher {
                    field: "tag.protocol",
                    value: MatchOn::Equal(protocol.to_string()),
                });
            }
            if let Some(message_timestamp) = &filter.message_timestamp {
                match_set.push(Matcher {
                    field: "messageTimestamp",
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
            // offset: None,
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
