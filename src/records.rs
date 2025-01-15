//! # Records

mod delete;
mod encryption;
mod query;
mod read;
mod subscribe;
pub(crate) mod write;

use std::collections::BTreeMap;
use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::delete::{Delete, DeleteDescriptor};
pub use self::encryption::{EncryptOptions, EncryptedKey, EncryptionProperty, Recipient, decrypt};
pub use self::query::{Query, QueryDescriptor};
pub use self::read::{Read, ReadDescriptor};
pub use self::subscribe::{Subscribe, SubscribeDescriptor, SubscribeReply};
pub use self::write::{Attestation, DelegatedGrant, SignaturePayload, Write, WriteDescriptor};
pub use crate::data::DataStream;
use crate::serde::rfc3339_micros_opt;
use crate::{Quota, RangeFilter, Result, utils};

// TODO: add builder for RecordsFilter

/// Records filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordsFilter {
    /// Whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// Records matching the specified author.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<Quota<String>>,

    /// Records matching the specified creator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,

    /// Records matching the specified recipient(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Quota<String>>,

    /// Entry matching the specified protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Entry protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,

    /// Records with the specified schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Get a single object by its ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,

    /// The CID of the parent object .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Records with the specified context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Match records with the specified tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, TagFilter>>,

    /// The MIME type of the requested data. For example, `application/json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_format: Option<String>,

    /// Records with a size within the range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<RangeFilter<usize>>,

    /// CID of the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_cid: Option<String>,

    /// Filter messages created within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<DateRange>,

    /// Filter messages published within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<DateRange>,

    /// Match messages updated within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<DateRange>,
}

impl RecordsFilter {
    /// Normalizes `RecordsFilter` protocol and schema URLs within a provided.
    pub(crate) fn normalize(&self) -> Result<Self> {
        let mut filter = self.clone();
        filter.protocol = if let Some(protocol) = &self.protocol {
            Some(utils::clean_url(protocol)?)
        } else {
            None
        };
        filter.schema =
            if let Some(schema) = &self.schema { Some(utils::clean_url(schema)?) } else { None };

        Ok(filter)
    }
}

/// Range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DateRange {
    /// The filter's lower bound.
    #[serde(rename = "from")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub lower: Option<DateTime<Utc>>,

    /// The filter's upper bound.
    #[serde(rename = "to")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub upper: Option<DateTime<Utc>>,
}

impl DateRange {
    /// Create a new range filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    /// Specify a 'greater-than' lower bound for the filter.
    #[must_use]
    pub const fn gt(mut self, gt: DateTime<Utc>) -> Self {
        self.lower = Some(gt);
        self
    }

    /// Specify a 'less-than' upper bound for the filter.
    #[must_use]
    pub const fn lt(mut self, lt: DateTime<Utc>) -> Self {
        self.upper = Some(lt);
        self
    }

    /// Check if the range contains the value.
    #[must_use]
    pub fn contains(&self, value: &DateTime<Utc>) -> bool {
        if let Some(lower) = &self.lower {
            if value < lower {
                return false;
            }
        }
        if let Some(upper) = &self.upper {
            if value > upper {
                return false;
            }
        }

        true
    }
}

/// `EntryType` sort.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Sort {
    /// Sort `date_created` from oldest to newest.
    CreatedAscending,

    /// Sort `date_created` newest to oldest.
    CreatedDescending,

    /// Sort `date_published` from oldest to newest.
    PublishedAscending,

    /// Sort `date_published` from newest to oldest.
    PublishedDescending,

    /// Sort `message_timestamp` from oldest to newest.
    #[default]
    TimestampAscending,

    /// Sort `message_timestamp` from newest to oldest.
    TimestampDescending,
}

impl Display for Sort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreatedAscending | Self::CreatedDescending => write!(f, "dateCreated"),
            Self::PublishedAscending | Self::PublishedDescending => write!(f, "datePublished"),
            Self::TimestampAscending | Self::TimestampDescending => write!(f, "messageTimestamp"),
        }
    }
}

/// Tag filter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TagFilter {
    /// Match tags starting with a string value.
    StartsWith(String),

    /// Filter tags by range.
    Range(RangeFilter<usize>),

    /// Filter by a specific value.
    Equal(Value),
}

impl Default for TagFilter {
    fn default() -> Self {
        Self::Equal(Value::Null)
    }
}

/// Implement  builder-like behaviour.
impl RecordsFilter {
    /// Returns a new [`RecordsFilter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one or more authors to the filter.
    #[must_use]
    pub fn add_author(mut self, author: impl Into<String>) -> Self {
        match &mut self.author {
            Some(Quota::Many(existing)) => {
                existing.push(author.into());
            }
            Some(Quota::One(existing)) => {
                self.author = Some(Quota::Many(vec![existing.clone(), author.into()]));
            }
            None => {
                self.author = Some(Quota::One(author.into()));
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
            Some(Quota::Many(existing)) => {
                existing.push(recipient.into());
            }
            Some(Quota::One(existing)) => {
                self.recipient = Some(Quota::Many(vec![existing.clone(), recipient.into()]));
            }
            None => {
                self.recipient = Some(Quota::One(recipient.into()));
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
    pub const fn data_size(mut self, data_size: RangeFilter<usize>) -> Self {
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
