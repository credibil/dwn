//! # Records Handlers
//!
//! Records handlers handle incoming `Records` interface messages.

mod delete;
mod encryption;
pub mod integrity;
mod query;
mod read;
mod subscribe;
pub mod write;

use std::collections::BTreeMap;
use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub use self::delete::{Delete, DeleteDescriptor};
pub use self::encryption::{EncryptOptions, EncryptionProperty, Recipient, decrypt};
pub use self::query::{Query, QueryDescriptor};
pub use self::read::{Read, ReadDescriptor};
pub use self::subscribe::{Subscribe, SubscribeDescriptor};
pub use self::write::{Attestation, DelegatedGrant, SignaturePayload, Tag, Write, WriteDescriptor};
use crate::{DateRange, OneOrMany, Range, Result, utils};

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

    /// Entry matching the specified protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Entry protocol path.
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
