//! # Store

use std::fmt::Display;
use std::ops::Deref;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::endpoint::Message;
use crate::messages::{self, MessagesFilter};
use crate::protocols::{self, ProtocolsFilter};
use crate::records::{self, RecordsFilter};
use crate::{Descriptor, Interface, Method, Quota, Range, Result};

/// `QuerySerializer` is used to provide overridable query serialization.
///
/// The default implementation serializes the query to a SQL string, but can be
/// overridden by implementers to provide custom serialization. For example, a
/// BSON query for `MongoDB`.
///
/// # Example
///
/// ```rust
/// use vercre_dwn::store::{Query,QuerySerializer};
///
/// struct CustomSerializer(Query);
///
/// QuerySerializer for CustomSerializer {
///    type Output = String;
///
///    fn serialize(&self) -> Self::Output {
///        format!("SELECT * FROM message WHERE protocol={}", self.0.protocol)
///    }
/// }
/// ```
pub trait QuerySerializer {
    /// The output type of the serialization.
    type Output;

    /// Serialize the query to the output type.
    fn serialize(&self) -> Self::Output;
}

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
    /// TODO: Add errors
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
}

impl Entry {
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

impl QuerySerializer for Query {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        match self {
            Self::Records(query) => query.serialize(),
            Self::Protocols(query) => query.serialize(),
            Self::Messages(query) => query.serialize(),
        }
    }
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

impl ProtocolsQuery {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    #[must_use]
    pub(crate) const fn published(mut self, published: bool) -> Self {
        self.published = Some(published);
        self
    }

    pub(crate) fn build(&self) -> Query {
        Query::Protocols(self.clone())
    }
}

impl From<ProtocolsFilter> for ProtocolsQuery {
    fn from(filter: ProtocolsFilter) -> Self {
        Self::new().protocol(filter.protocol)
    }
}

impl QuerySerializer for ProtocolsQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = format!(
            "SELECT * FROM message
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'\n",
            interface = Interface::Protocols,
            method = Method::Configure
        );

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND descriptor.definition.protocol = '{protocol}'\n"));
        }

        if let Some(published) = &self.published {
            sql.push_str(&format!("AND descriptor.definition.published = {published}\n"));
        }

        sql.push_str("ORDER BY descriptor.messageTimestamp COLLATE DESC");
        sql
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
    pub date_created: Option<Range<String>>,

    /// Filter records by `archived`.
    pub archived: Option<bool>,

    filter: Option<RecordsFilter>,
    sort: Option<Sort>,
    pagination: Option<Pagination>,
}

impl Default for RecordsQuery {
    fn default() -> Self {
        let sort = Sort {
            message_timestamp: Some(Direction::Descending),
            ..Sort::default()
        };

        Self {
            method: Some(Method::Write),
            archived: Some(false),
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
    pub(crate) fn date_created(mut self, date_created: Range<String>) -> Self {
        self.date_created = Some(date_created);
        self
    }

    #[must_use]
    pub(crate) const fn method(mut self, method: Option<Method>) -> Self {
        self.method = method;
        self
    }

    #[must_use]
    pub(crate) const fn archived(mut self, archived: Option<bool>) -> Self {
        self.archived = archived;
        self
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn sort(mut self, sort: Sort) -> Self {
        self.sort = Some(sort);
        self
    }

    pub(crate) fn build(&self) -> Query {
        Query::Records(self.clone())
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

impl QuerySerializer for RecordsQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let min_date = &DateTime::<Utc>::MIN_UTC.to_rfc3339();
        let max_date = &Utc::now().to_rfc3339();

        let mut sql = format!(
            "SELECT * FROM message\n WHERE descriptor.interface = '{interface}'\n",
            interface = Interface::Records
        );

        if let Some(archived) = &self.archived {
            sql.push_str(&format!("AND archived = {archived}\n"));
        }

        if let Some(method) = &self.method {
            sql.push_str(&format!("AND descriptor.method = '{method}'\n"));
        }

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!("AND recordId = '{record_id}'\n"));
        }

        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!("AND descriptor.parentId = '{parent_id}'\n"));
        }

        if let Some(context_id) = &self.context_id {
            let min_ctx = &"\u{0000}".to_string();
            let max_ctx = &"\u{ffff}".to_string();

            let min = context_id.min.as_ref().unwrap_or(min_ctx);
            let max = context_id.max.as_ref().unwrap_or(max_ctx);
            sql.push_str(&format!("AND contextId BETWEEN '{min}' AND '{max}'\n"));
        }

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND descriptor.protocol = '{protocol}'\n"));
        }

        if let Some(protocol_path) = &self.protocol_path {
            sql.push_str(&format!("AND descriptor.protocolPath = '{protocol_path}'\n"));
        }

        if let Some(recipient) = &self.recipient {
            sql.push_str(&quota("descriptor.recipient", recipient));
        }

        if let Some(date_created) = &self.date_created {
            let from = date_created.min.as_ref().unwrap_or(min_date);
            let to = date_created.max.as_ref().unwrap_or(max_date);
            sql.push_str(&format!("AND descriptor.dateCreated BETWEEN '{from}' AND '{to}'\n"));
        }

        // include `RecordsFilter` sql
        if let Some(filter) = &self.filter {
            sql.push_str(&format!("{}\n", QuerySerializer::serialize(filter)));
        }

        // sorting
        if let Some(sort) = &self.sort {
            let mut fields = vec![];
            if let Some(dir) = &sort.date_created {
                fields.push(format!("descriptor.dateCreated COLLATE {dir}"));
            }
            if let Some(dir) = &sort.date_published {
                fields.push(format!("descriptor.datePublished COLLATE {dir}"));
            }
            if let Some(dir) = &sort.message_timestamp {
                fields.push(format!("descriptor.messageTimestamp COLLATE {dir}"));
            }
            sql.push_str(&format!("ORDER BY {sort}\n", sort = fields.join(",")));
        }

        if let Some(pagination) = &self.pagination {
            if let Some(limit) = pagination.limit {
                sql.push_str(&format!("LIMIT {limit} "));
            }

            if let Some(offset) = pagination.offset {
                sql.push_str(&format!("START {offset}\n"));
            }
        }

        sql
    }
}

/// `MessagesQuery` use a builder to simplify the process of creating
/// `EventStore` queries.
#[derive(Clone, Debug, Default)]
pub struct MessagesQuery {
    filters: Vec<MessagesFilter>,
}

impl MessagesQuery {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn build(&self) -> Query {
        Query::Messages(self.clone())
    }
}

impl From<messages::Query> for MessagesQuery {
    fn from(query: messages::Query) -> Self {
        let mut mq = Self::new();
        mq.filters = query.descriptor.filters;
        mq
    }
}

impl QuerySerializer for MessagesQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = "SELECT * FROM event_log ".to_string();

        for filter in &self.filters {
            if sql.is_empty() {
                sql.push_str("WHERE\n");
            } else {
                sql.push_str("OR\n");
            }
            sql.push_str(&format!("({filter})", filter = QuerySerializer::serialize(filter)));
        }

        sql.push_str("ORDER BY descriptor.messageTimestamp COLLATE ASC");
        sql
    }
}

fn quota(field: &str, clause: &Quota<String>) -> String {
    match clause {
        Quota::One(value) => {
            format!("AND {field} = '{value}'\n")
        }
        Quota::Many(values) => {
            let mut sql = String::new();
            sql.push_str(&format!("{field}  IN ("));
            for value in values {
                sql.push_str(&format!("'{value}',"));
            }
            sql.pop(); // remove trailing comma
            sql.push_str(")\n");

            sql
        }
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
    Ascending,

    /// Sort descending.
    #[default]
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
