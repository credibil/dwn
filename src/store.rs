//! # Store

use std::fmt::Display;
use std::ops::Deref;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::endpoint::Message;
pub use crate::messages::MessagesFilter;
pub use crate::protocols::ProtocolsFilter;
use crate::records::{self, Delete, Write};
pub use crate::records::{RecordsFilter, TagFilter};
use crate::{Descriptor, Method, Quota, Range, Result, authorization, messages, protocols};

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

    /// Indexes derived from the associated message object, flattened for
    /// ease of querying.
    #[serde(flatten)]
    #[serde(skip_deserializing)]
    pub indexes: Map<String, Value>,
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

impl From<&Write> for Entry {
    fn from(write: &Write) -> Self {
        let mut record = Self {
            message: EntryType::Write(write.clone()),
            indexes: Map::new(),
        };

        // FIXME: build full indexes for each record
        record.indexes.insert(
            "author".to_string(),
            Value::String(write.authorization.author().unwrap_or_default()),
        );

        if let Some(attestation) = &write.attestation {
            let attester = authorization::signer_did(attestation).unwrap_or_default();
            record.indexes.insert("attester".to_string(), Value::String(attester));
        }

        let date_updated =
            write.descriptor.base.message_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true);
        record.indexes.insert("dateUpdated".to_string(), Value::String(date_updated));

        if let Some(tags) = &write.descriptor.tags {
            let mut tag_map = Map::new();
            for (k, v) in tags {
                tag_map.insert(format!("tag.{k}"), v.clone());
            }
            record.indexes.insert("tags".to_string(), Value::Object(tag_map));
        }

        record
    }
}

impl From<&Delete> for Entry {
    fn from(delete: &Delete) -> Self {
        let mut record = Self {
            message: EntryType::Delete(delete.clone()),
            indexes: Map::new(),
        };

        // FIXME: build full indexes for each record
        // flatten record_id so it queries correctly
        record
            .indexes
            .insert("recordId".to_string(), Value::String(delete.descriptor.record_id.clone()));
        record.indexes.insert("archived".to_string(), Value::Bool(false));

        record
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
    Messages(MessagesQuery),
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

impl From<ProtocolsQuery> for Query {
    fn from(query: ProtocolsQuery) -> Self {
        Self::Protocols(query)
    }
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
    /// Filter records by `method`.
    pub method: Option<Method>,

    /// Filter records by `record_id`.
    pub record_id: Option<String>,

    /// Filter records by `parent_id`.
    pub parent_id: Option<String>,

    /// Filter records by `context_id`.
    pub context_id: Option<Range<String>>,

    /// Filter records by or more `recipient`s.
    pub recipient: Option<Quota<String>>,

    /// Filter records by `protocol`.
    pub protocol: Option<String>,

    /// Filter records by `protocol_path`.
    pub protocol_path: Option<String>,

    /// Filter records by `date_created`.
    pub date_created: Option<Range<DateTime<Utc>>>,

    /// Include records with the `archive` flag (initial write that has been
    /// superseded).
    pub include_archived: bool,

    /// Filter records by `filter`.
    pub filter: Option<RecordsFilter>,

    /// Sort options.
    pub sort: Option<Sort>,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl Default for RecordsQuery {
    fn default() -> Self {
        let sort = Sort {
            message_timestamp: Some(Direction::Ascending),
            ..Sort::default()
        };

        Self {
            method: Some(Method::Write),
            include_archived: false,
            sort: Some(sort),
            record_id: None,
            parent_id: None,
            context_id: None,
            recipient: None,
            protocol: None,
            protocol_path: None,
            date_created: None,
            filter: None,
            pagination: None,
        }
    }
}

impl RecordsQuery {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    #[must_use]
    pub(crate) fn parent_id(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    #[must_use]
    pub(crate) fn context_id(mut self, context_id: Range<String>) -> Self {
        self.context_id = Some(context_id);
        self
    }

    #[must_use]
    pub(crate) fn add_recipient(mut self, recipient: impl Into<String>) -> Self {
        match self.recipient {
            Some(Quota::One(value)) => {
                self.recipient = Some(Quota::Many(vec![value, recipient.into()]));
            }
            Some(Quota::Many(mut values)) => {
                values.push(recipient.into());
                self.recipient = Some(Quota::Many(values));
            }
            None => {
                self.recipient = Some(Quota::One(recipient.into()));
            }
        }
        self
    }

    #[must_use]
    pub(crate) fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    #[must_use]
    pub(crate) fn protocol_path(mut self, protocol_path: impl Into<String>) -> Self {
        self.protocol_path = Some(protocol_path.into());
        self
    }

    #[must_use]
    pub(crate) const fn date_created(mut self, date_created: Range<DateTime<Utc>>) -> Self {
        self.date_created = Some(date_created);
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
    #[allow(dead_code)]
    pub(crate) const fn sort(mut self, sort: Sort) -> Self {
        self.sort = Some(sort);
        self
    }
}

impl From<records::Query> for RecordsQuery {
    fn from(query: records::Query) -> Self {
        Self {
            filter: Some(query.descriptor.filter),
            sort: query.descriptor.date_sort,
            pagination: query.descriptor.pagination,
            ..Self::default()
        }
    }
}

impl From<records::Read> for RecordsQuery {
    fn from(read: records::Read) -> Self {
        Self {
            filter: Some(read.descriptor.filter),
            ..Self::default()
        }
    }
}

impl From<RecordsQuery> for Query {
    fn from(query: RecordsQuery) -> Self {
        Self::Records(query)
    }
}

/// `MessagesQuery` use a builder to simplify the process of creating
/// `EventStore` queries.
#[derive(Clone, Debug, Default)]
pub struct MessagesQuery {
    /// Message filters.
    pub filters: Vec<MessagesFilter>,
}

impl From<messages::Query> for MessagesQuery {
    fn from(query: messages::Query) -> Self {
        Self {
            filters: query.descriptor.filters,
        }
    }
}

impl From<MessagesQuery> for Query {
    fn from(query: MessagesQuery) -> Self {
        Self::Messages(query)
    }
}

/// `EntryType` sort.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    /// Sort by `date_created`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<Direction>,

    /// Sort by `date_published`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<Direction>,

    /// Sort by `message_timestamp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<Direction>,
}

/// Sort direction.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// Sort ascending.
    #[default]
    Ascending,

    /// Sort descending.
    Descending,
}

impl Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ascending => write!(f, "ASC"),
            Self::Descending => write!(f, "DESC"),
        }
    }
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// The offset from the start of the result set from which to start when
    /// determining the page of results to return.
    #[serde(skip)]
    pub offset: Option<usize>,

    /// Cursor created form the previous page of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
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

    /// The value from the sort field of the last entry in the previous
    /// page of results.
    #[serde(rename = "value")]
    pub sort_value: String,
}
