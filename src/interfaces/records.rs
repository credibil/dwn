//! # Records
//!
//! The records delete endpoint handles `RecordsDelete` messages — requests
//! to delete a [`Write`] record.
//!
//! Technically, the [`Write`] record is not deleted, but rather a new
//! [`Delete`] record is created to mark the record as deleted. The [`Delete`]
//! record is used to prune the record and its descendants from the system,
//! leaving only the [`Delete`] and initial [`Write`] records.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::io;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use credibil_jose::jwe::{self, Protected};
use credibil_jose::{Jws, PublicKeyJwk};
use credibil_se::{AlgAlgorithm, Curve, EncAlgorithm, PublicKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::api::Result;
use crate::authorization::{Authorization, JwsPayload};
use crate::event::Subscriber;
use crate::hd_key::DerivationScheme;
use crate::interfaces::Descriptor;
use crate::serde::{rfc3339_micros, rfc3339_micros_opt};
use crate::store::{Cursor, DateRange, Pagination, Range};
use crate::utils::cid;
use crate::{OneOrMany, bad_request, utils};

/// The [`Delete`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delete {
    /// Delete descriptor.
    pub descriptor: DeleteDescriptor,

    /// Message authorization.
    pub authorization: Authorization,

    /// Flattened fields as key/value pairs to use for indexing stored records.
    #[serde(skip)]
    #[cfg(feature = "server")]
    pub(crate) indexes: HashMap<String, String>,
}

impl Delete {
    /// Compute the content identifier (CID) for the `Delete` message.
    ///
    /// # Errors
    ///
    /// This method will fail if the message cannot be serialized to CBOR.
    pub fn cid(&self) -> anyhow::Result<String> {
        cid::from_value(self)
    }
}

/// The [`Delete`] message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The ID of the record to delete.
    pub record_id: String,

    /// Specifies whether descendent records should be pruned or not.
    pub prune: bool,
}

/// [`DeleteReply`] is returned by the handler in the
/// [`crate::endpoint::Reply`] `body` field.
#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteReply;

/// The [`Query`] message expected by the handler.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// The [`Query`] message descriptor.
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

/// [`QueryReply`] is returned by the handler in the [`crate::endpoint::Reply`]
/// `body` field.
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

/// [`QueryReplyEntry`] represents a [`Write`] entry returned by the query.
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

/// The Records filter is used when querying for records.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordsFilter {
    /// Find a single record by its ID. May return two results — an initial
    /// write and the latest update or Delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,

    /// Records matching the specified author.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<OneOrMany<String>>,

    /// Records matching the specified creator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,

    /// Records matching the specified recipient(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<OneOrMany<String>>,

    /// Records with the specified context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// The CID of the parent object .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Storable matching the specified protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Storable protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,

    /// Records with the specified schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// The MIME type of the requested data. For example, `application/json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_format: Option<String>,

    /// Match records with the specified tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, TagFilter>>,

    /// CID of the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_cid: Option<String>,

    /// Records with a size within the range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<Range<usize>>,

    /// Whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// Filter messages published within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<DateRange>,

    /// Filter messages created within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<DateRange>,

    /// Match messages updated within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<DateRange>,
}

impl RecordsFilter {
    /// Create a new [`RecordsFilter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalizes protocol and schema URLs within the `RecordsFilter`.
    #[cfg(feature = "client")]
    pub(crate) fn normalize(&self) -> Result<Self> {
        let mut filter = self.clone();
        filter.protocol = if let Some(protocol) = &self.protocol {
            Some(utils::uri::clean(protocol)?)
        } else {
            None
        };
        filter.schema =
            if let Some(schema) = &self.schema { Some(utils::uri::clean(schema)?) } else { None };
        Ok(filter)
    }

    /// Check whether the filter will return a concise set of results.
    #[cfg(feature = "server")]
    pub(crate) const fn is_concise(&self) -> bool {
        self.record_id.is_some()
            || self.protocol_path.is_some()
            || self.context_id.is_some()
            || self.parent_id.is_some()
            || self.schema.is_some()
    }

    /// Create an optimized filter to use with single-field indexes. This
    /// method chooses the best filter property, in order of priority, to use
    /// when querying.
    #[cfg(feature = "server")]
    pub(crate) fn as_concise(&self) -> Option<(String, String)> {
        if let Some(record_id) = &self.record_id {
            return Some(("recordId".to_string(), record_id.clone()));
        }
        if let Some(protocol_path) = &self.protocol_path {
            return Some(("protocolPath".to_string(), protocol_path.clone()));
        }
        if let Some(context_id) = &self.context_id {
            return Some(("contextId".to_string(), context_id.clone()));
        }
        if let Some(parent_id) = &self.parent_id {
            return Some(("parentId".to_string(), parent_id.clone()));
        }
        if let Some(schema) = &self.schema {
            return Some(("schema".to_string(), schema.clone()));
        }
        None
    }
}

/// Implement  builder-like behaviour.
impl RecordsFilter {
    /// Add one or more authors to the filter.
    #[must_use]
    pub fn add_author(mut self, author: impl Into<String>) -> Self {
        match &mut self.author {
            Some(OneOrMany::Many(existing)) => {
                existing.push(author.into());
            }
            Some(OneOrMany::One(existing)) => {
                self.author = Some(OneOrMany::Many(vec![existing.clone(), author.into()]));
            }
            None => {
                self.author = Some(OneOrMany::One(author.into()));
            }
        }
        self
    }

    /// Add an attester to the filter.
    #[must_use]
    pub fn attester(mut self, attester: impl Into<String>) -> Self {
        self.attester = Some(attester.into());
        self
    }

    /// Add one or more recipients to the filter.
    #[must_use]
    pub fn add_recipient(mut self, recipient: impl Into<String>) -> Self {
        match &mut self.recipient {
            Some(OneOrMany::Many(existing)) => {
                existing.push(recipient.into());
            }
            Some(OneOrMany::One(existing)) => {
                self.recipient = Some(OneOrMany::Many(vec![existing.clone(), recipient.into()]));
            }
            None => {
                self.recipient = Some(OneOrMany::One(recipient.into()));
            }
        }
        self
    }

    /// Add a protocol to the filter.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Add a protocol path to the filter.
    #[must_use]
    pub fn protocol_path(mut self, protocol_path: impl Into<String>) -> Self {
        self.protocol_path = Some(protocol_path.into());
        self
    }

    /// Specify a protocol schema on the filter.
    #[must_use]
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Add a published flag to the filter.
    #[must_use]
    pub const fn published(mut self, published: bool) -> Self {
        self.published = Some(published);
        self
    }

    /// Add a context ID to the filter.
    #[must_use]
    pub fn context_id(mut self, context_id: impl Into<String>) -> Self {
        self.context_id = Some(context_id.into());
        self
    }

    /// Add a record ID to the filter.
    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    /// Add a parent ID to the filter.
    #[must_use]
    pub fn parent_id(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Add a tag to the filter.
    #[must_use]
    pub fn add_tag(mut self, key: impl Into<String>, value: TagFilter) -> Self {
        if let Some(existing) = &mut self.tags {
            existing.insert(key.into(), value);
        } else {
            let mut tags = BTreeMap::new();
            tags.insert(key.into(), value);
            self.tags = Some(tags);
        }
        self
    }

    /// Add a data format to the filter.
    #[must_use]
    pub fn data_format(mut self, data_format: impl Into<String>) -> Self {
        self.data_format = Some(data_format.into());
        self
    }

    /// Add a data size to the filter.
    #[must_use]
    pub const fn data_size(mut self, data_size: Range<usize>) -> Self {
        self.data_size = Some(data_size);
        self
    }

    /// Add a data CID to the filter.
    #[must_use]
    pub fn data_cid(mut self, data_cid: impl Into<String>) -> Self {
        self.data_cid = Some(data_cid.into());
        self
    }

    /// Add a date created to the filter.
    #[must_use]
    pub const fn date_created(mut self, date_created: DateRange) -> Self {
        self.date_created = Some(date_created);
        self
    }

    /// Add a date published to the filter.
    #[must_use]
    pub const fn date_published(mut self, date_published: DateRange) -> Self {
        self.date_published = Some(date_published);
        self
    }

    /// Add a date updated to the filter.
    #[must_use]
    pub const fn date_updated(mut self, date_updated: DateRange) -> Self {
        self.date_updated = Some(date_updated);
        self
    }
}

/// Specifies the way that `RecordsQuery`results should be sorted.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Sort {
    /// Sort `date_created` from oldest to newest.
    #[serde(rename = "createdAscending")]
    CreatedAsc,

    /// Sort `date_created` newest to oldest.
    #[serde(rename = "createdDescending")]
    CreatedDesc,

    /// Sort `date_published` from oldest to newest.
    #[serde(rename = "publishedAscending")]
    PublishedAsc,

    /// Sort `date_published` from newest to oldest.
    #[serde(rename = "publishedDescending")]
    PublishedDesc,

    /// Sort `message_timestamp` from oldest to newest.
    #[serde(rename = "timestampAscending")]
    #[default]
    TimestampAsc,

    /// Sort `message_timestamp` from newest to oldest.
    #[serde(rename = "timestampDescending")]
    TimestampDesc,
}

impl Sort {
    /// Short-circuit testing for ascending/descending sort.
    #[must_use]
    pub const fn is_ascending(&self) -> bool {
        matches!(self, Self::CreatedAsc | Self::PublishedAsc | Self::TimestampAsc)
    }
}

impl Display for Sort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreatedAsc | Self::CreatedDesc => write!(f, "dateCreated"),
            Self::PublishedAsc | Self::PublishedDesc => write!(f, "datePublished"),
            Self::TimestampAsc | Self::TimestampDesc => write!(f, "messageTimestamp"),
        }
    }
}

/// A tag filter is used when filter records by tag.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TagFilter {
    /// Match tags starting with a string value.
    StartsWith(String),

    /// Filter tags by range.
    Range(Range<usize>),

    /// Filter by a specific value.
    Equal(Tag),
}

impl Default for TagFilter {
    fn default() -> Self {
        Self::Equal(Tag::Empty)
    }
}

/// The [`Read`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Read {
    /// Read descriptor.
    pub descriptor: ReadDescriptor,

    /// Message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// The [`Read`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Defines the filter for the read.
    pub filter: RecordsFilter,
}

/// [`ReadReply`] is returned by the handler in the [`crate::endpoint::Reply`]
/// `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReply {
    /// The read reply entry.
    pub entry: ReadReplyEntry,
}

/// [`ReadReplyEntry`] represents the [`Write`] entry returned for a successful
/// 'read'.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReplyEntry {
    /// The latest `RecordsWrite` message of the record if record exists
    /// (not deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_write: Option<Write>,

    /// The `RecordsDelete` if the record is deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_delete: Option<Delete>,

    /// The initial write of the record if the returned `RecordsWrite` message
    /// itself is not the initial write or if a `RecordsDelete` is returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_write: Option<Write>,

    /// The data for the record.
    #[serde(skip)]
    pub data: Option<io::Cursor<Vec<u8>>>,
}

/// The [`Subscribe`] message expected by the handler.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// The [`Subscribe`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for subscribe.
    pub filter: RecordsFilter,
}

/// [`SubscribeReply`] is returned by the handler in the
/// [`crate::endpoint::Reply`] `body` field.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    /// N.B. serialization/deserialization is skipped because the subscriber
    /// `Stream` is not serializable.
    #[serde(skip)]
    pub subscription: Subscriber,
}

/// The [`Write`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Write {
    /// Write descriptor.
    pub descriptor: WriteDescriptor,

    /// The message authorization.
    pub authorization: Authorization,

    /// The Storable CID for the record.
    pub record_id: String,

    /// Storable context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Storable attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Storable encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionProperty>,

    /// The base64url encoded data of the record if the data associated with
    /// the record is equal or smaller than `MAX_ENCODING_SIZE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,

    /// The data stream of the record if the data associated with the record
    #[serde(skip)]
    pub data_stream: Option<io::Cursor<Vec<u8>>>,

    /// Flattened fields as key/value pairs to use for indexing stored records.
    #[serde(skip)]
    #[cfg(feature = "server")]
    pub(crate) indexes: HashMap<String, String>,
}

impl Write {
    /// Compute the content identifier (CID) for the `Write` message.
    ///
    /// # Errors
    ///
    /// This method will fail if the message cannot be serialized to CBOR.
    pub fn cid(&self) -> anyhow::Result<String> {
        let mut write = self.clone();
        write.encoded_data = None;
        cid::from_value(&write)
    }

    /// Computes the deterministic Storable ID (Record ID) of the message.
    ///
    /// # Errors
    ///
    /// Returns an error if the Storable ID cannot be serialized to CBOR.
    pub fn entry_id(&self, author: &str) -> Result<String> {
        #[derive(Serialize)]
        struct EntryId<'a> {
            #[serde(flatten)]
            descriptor: &'a WriteDescriptor,
            author: &'a str,
        }
        Ok(utils::cid::from_value(&EntryId {
            descriptor: &self.descriptor,
            author,
        })?)
    }
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignaturePayload {
    /// The standard signature payload.
    #[serde(flatten)]
    pub base: JwsPayload,

    /// The ID of the record being signed.
    pub record_id: String,

    /// The context ID of the record being signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Attestation CID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_cid: Option<String>,

    /// Encryption CID .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_cid: Option<String>,
}

/// Attestation payload.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The attestation's descriptor CID.
    pub descriptor_cid: String,
}

/// Delegated Grant is a special case of [`Write`] used in [`Authorization`]
/// and [`Attestation`] grant references.
///
/// It is structured to cope with recursive references to [`Authorization`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedGrant {
    /// The grant's descriptor.
    pub descriptor: WriteDescriptor,

    ///The grant's authorization.
    pub authorization: Box<Authorization>,

    /// CID referencing the record associated with the message.
    pub record_id: String,

    /// Context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Encoded grant data.
    pub encoded_data: String,
}

/// The [`Write`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Storable's protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// The protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,

    /// The record's recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// The record's schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Tags associated with the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Tag>>,

    /// The CID of the record's parent (if exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// CID of the record's data.
    pub data_cid: String,

    /// The record's size in bytes.
    pub data_size: usize,

    /// The record's MIME type. For example, `application/json`.
    pub data_format: String,

    /// The datatime the record was created.
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_created: DateTime<Utc>,

    /// Indicates whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// The datetime of publishing, if published.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub date_published: Option<DateTime<Utc>>,
}

/// Tag value types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
// #[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Tag {
    /// Empty tag value.
    #[default]
    Empty,

    /// String tag value.
    String(String),

    /// Number tag value.
    Number(u64),

    /// Boolean tag value.
    Boolean(bool),
}

impl Tag {
    /// Attempt to convert the tag value to a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Attempt to convert the tag value to a u64.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Attempt to convert the tag value to a bool.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

impl From<String> for Tag {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}
impl From<&str> for Tag {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}
impl From<u64> for Tag {
    fn from(value: u64) -> Self {
        Self::Number(value)
    }
}
impl From<bool> for Tag {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

/// For consistency, [`WriteReply`] is returned by the handler in the
/// [`crate::endpoint::Reply`] `body` field, but contains no data.
#[derive(Debug, Deserialize, Serialize)]
pub struct WriteReply;

/// Encryption settings.
#[derive(Clone, Debug, Default)]
pub struct EncryptOptions<'a> {
    /// The algorithm to use to encrypt the message data.
    content_algorithm: EncAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    key_algorithm: AlgAlgorithm,

    /// The data to encrypt.
    data: &'a [u8],

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    recipients: Vec<Recipient>,
}

/// Encrypted data. Intermediate work product.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encrypted {
    /// The algorithm to use to encrypt the message data.
    #[zeroize(skip)]
    content_algorithm: EncAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    #[zeroize(skip)]
    key_algorithm: AlgAlgorithm,

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    #[zeroize(skip)]
    pub recipients: Vec<Recipient>,

    /// The content encryption key (CEK) used to encrypt the data.
    pub cek: Vec<u8>,

    /// The initialization vector (IV) used to encrypt the data.
    pub iv: String,

    /// The additional authenticated data (AAD) used to encrypt the data.
    pub tag: String,

    /// The ciphertext.
    pub ciphertext: Vec<u8>,
}

/// Encryption key settings.
#[derive(Clone, Debug, Default)]
pub struct Recipient {
    /// The identifier of the recipient's public key used to encrypt the
    /// content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key used to encrypt the CEK.
    pub public_key: PublicKeyJwk,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,
}

impl<'a> EncryptOptions<'a> {
    /// Create a new `EncryptionOptions`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_algorithm: EncAlgorithm::A256Gcm,
            key_algorithm: AlgAlgorithm::EcdhEsA256Kw,
            data: &[],
            recipients: vec![],
        }
    }

    /// Set the content encryption algorithm.
    #[must_use]
    pub const fn content_algorithm(mut self, algorithm: EncAlgorithm) -> Self {
        self.content_algorithm = algorithm;
        self
    }

    /// Set the key encryption algorithm.
    #[must_use]
    pub const fn key_algorithm(mut self, algorithm: AlgAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// Set the data to encrypt.
    #[must_use]
    pub const fn data(mut self, data: &'a [u8]) -> Self {
        self.data = data;
        self
    }

    /// Add a recipient to the encryption options.
    #[must_use]
    pub fn with_recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Encrypt the data using the specified encryption options, retaining the
    /// CEK, IV, and AAD tag for later use.
    ///
    /// # Errors
    ///
    /// Will fail if the [`Protected`] struct cannot be serialized to JSON or
    /// if the provided data cannot be encrypted using the specified content
    /// encryption algorithm.
    pub fn encrypt(&mut self) -> Result<Encrypted> {
        let (cek, _) = self.key_algorithm.generate_cek(&PublicKey::empty());
        let protected = Protected {
            enc: self.content_algorithm.clone(),
            alg: None,
        };
        let aad = serde_json::to_vec(&protected)?;

        let plaintext = serde_json::to_vec(self.data)?;
        let encrypted = self.content_algorithm.encrypt(&plaintext, &cek, &aad)?;

        Ok(Encrypted {
            content_algorithm: self.content_algorithm.clone(),
            key_algorithm: self.key_algorithm.clone(),
            recipients: self.recipients.clone(),
            cek: cek.to_vec(),
            iv: Base64UrlUnpadded::encode_string(&encrypted.iv),
            tag: Base64UrlUnpadded::encode_string(&encrypted.tag),
            ciphertext: encrypted.ciphertext,
        })
    }
}

impl Encrypted {
    /// Add a recipient to the encryption options.
    #[must_use]
    pub fn add_recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Finalize the encryption process, returning the encryption properties
    ///
    /// # Errors
    ///
    /// Will fail if the CEK cannot be encrypted.
    pub fn finalize(self) -> Result<EncryptionProperty> {
        // encryption property
        let mut encryption = EncryptionProperty {
            algorithm: self.content_algorithm.clone(),
            initialization_vector: self.iv.clone(),
            message_authentication_code: Some(self.tag.clone()),
            key_encryption: vec![],
        };

        // add `EncryptedKey` for each recipient
        for recipient in &self.recipients {
            // recipient's public key
            let jwk = &recipient.public_key;
            let decoded = if jwk.crv == Curve::Ed25519 {
                Base64UrlUnpadded::decode_vec(&jwk.x)?
            } else {
                let mut decoded = Base64UrlUnpadded::decode_vec(&jwk.x)?;
                let Some(y) = &jwk.y else {
                    return Err(bad_request!("missing y"));
                };
                decoded.extend(&Base64UrlUnpadded::decode_vec(y)?);
                decoded
            };

            // create `jwe::Recipient` for call to jwe key wrapping function
            let recip = jwe::Recipient {
                key_id: recipient.key_id.clone(),
                public_key: PublicKey::try_from(decoded)?,
            };
            let cek: [u8; 32] =
                self.cek.clone().try_into().map_err(|_| bad_request!("invalid CEK key"))?;

            // encrypt cek
            let ke = match self.key_algorithm {
                AlgAlgorithm::EcdhEsA256Kw => jwe::ecdh_a256kw(&cek, &recip)?,
                AlgAlgorithm::EciesEs256K => jwe::ecies_es256k(&cek, &recip)?,
                AlgAlgorithm::EcdhEs => {
                    return Err(bad_request!("ECDH-ES requires a single recipient"));
                }
            };

            // unpack `jwe::KeyEncryption` into `EncryptedKey`
            let mut encrypted = EncryptedKey {
                root_key_id: recipient.key_id.clone(),
                algorithm: ke.header.alg.clone(),
                ephemeral_public_key: ke.header.epk.clone(),
                initialization_vector: ke.header.iv.clone(),
                message_authentication_code: ke.header.tag.clone(),
                cek: ke.encrypted_key.clone(),
                derivation_scheme: recipient.derivation_scheme.clone(),
                derived_public_key: None,
            };

            // attach the public key when derivation scheme is protocol-context,
            // so that the responder to this message is able to encrypt the
            // content encryption key using the same protocol-context derived
            // public key, without needing the knowledge of the corresponding
            // private key
            if recipient.derivation_scheme == DerivationScheme::ProtocolContext {
                encrypted.derived_public_key = Some(recipient.public_key.clone());
            }

            encryption.key_encryption.push(encrypted);
        }

        Ok(encryption)
    }
}

/// `EncryptionProperty` contains information about the encryption used when
/// encrypting a `Write` message. The information is used by the recipient
/// to decrypt the message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProperty {
    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `enc` property).
    pub algorithm: EncAlgorithm,

    /// The initialization vector used to encrypt the data.
    pub initialization_vector: String,

    /// One or more objects, each containing information about the
    /// Content Encryption Key (CEK) used to encrypt the data.
    pub key_encryption: Vec<EncryptedKey>,

    /// The message authentication code.
    /// Equivalent to the JWE Authentication Tag (JWE `tag` property).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_authentication_code: Option<String>,
}

/// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
/// Encrypted Key (JWE `encrypted_key` property), this is the key used to
/// encrypt the data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id)
    /// of the root public key used to encrypt the symmetric encryption key.
    pub root_key_id: String,

    /// The derived public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_public_key: Option<PublicKeyJwk>,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,

    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `alg` property).
    pub algorithm: AlgAlgorithm,

    /// The ephemeral public key used to encrypt the data.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The initialization vector used to encrypt the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<String>,

    /// The message authentication code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_authentication_code: Option<String>,

    /// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
    /// Encrypted Key (JWE `encrypted_key` property), this is the key used to
    /// encrypt the data.
    #[serde(rename = "encryptedKey")]
    pub cek: String,
}
