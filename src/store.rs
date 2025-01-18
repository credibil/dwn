//! # Store

mod block;
mod index;
mod message;
pub mod serializer;

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// pub use self::serializer::{Clause, Dir, Op, Serialize, Serializer, Value};
use crate::endpoint::Message;
pub use crate::messages::MessagesFilter;
pub use crate::protocols::ProtocolsFilter;
use crate::records::{self, Delete, Write};
pub use crate::records::{RecordsFilter, Sort, TagFilter};
use crate::{Descriptor, Method, Result, authorization, messages, protocols};
pub use crate::{Lower, RangeFilter, Upper};

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

// LATER: perhaps should be TryFrom?
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
        record
            .indexes
            .insert("messageCid".to_string(), Value::String(write.cid().unwrap_or_default()));

        if let Some(attestation) = &write.attestation {
            let attester = authorization::signer_did(attestation).unwrap_or_default();
            record.indexes.insert("attester".to_string(), Value::String(attester));
        }

        // --------------------------------------------------------------------
        // LATER: `dateUpdated` should not be needed as we use `message_timestamp`
        // let date_updated =
        //     write.descriptor.base.message_timestamp.to_rfc3339_opts(SecondsFormat::Micros, true);
        // record.indexes.insert("dateUpdated".to_string(), Value::String(date_updated));
        // --------------------------------------------------------------------

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
    /// Filter records using one or more filters OR'ed together.
    pub filters: Vec<RecordsFilter>,

    /// Method of to use when querying records. Defaults to `RecordsWrite`, but
    /// can be set to `RecordsDelete` or None (for both).
    pub method: Option<Method>,

    /// Include records with the `archive` flag (i.e. include initial write for
    /// updated records).
    pub include_archived: bool,

    /// Sort options.
    pub sort: Option<Sort>,

    /// Pagination options.
    pub pagination: Option<Pagination>,
}

impl Default for RecordsQuery {
    fn default() -> Self {
        Self {
            method: Some(Method::Write),
            include_archived: false,
            sort: Some(Sort::default()),
            filters: vec![],
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
    #[allow(dead_code)]
    pub(crate) const fn sort(mut self, sort: Sort) -> Self {
        self.sort = Some(sort);
        self
    }
}

impl From<records::Query> for RecordsQuery {
    fn from(query: records::Query) -> Self {
        Self {
            filters: vec![query.descriptor.filter],
            sort: query.descriptor.date_sort,
            pagination: query.descriptor.pagination,
            ..Self::default()
        }
    }
}

impl From<records::Read> for RecordsQuery {
    fn from(read: records::Read) -> Self {
        Self {
            filters: vec![read.descriptor.filter],
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
    // /// The offset from the start of the result set from which to start when
    // /// determining the page of results to return.
    // #[serde(skip)]
    // pub offset: Option<usize>,
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

    // /// Set the offset.
    // #[must_use]
    // pub const fn offset(mut self, offset: usize) -> Self {
    //     self.offset = Some(offset);
    //     self
    // }
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
