//! # Records

mod delete;
mod query;
mod read;
mod subscribe;
pub(crate) mod write;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::delete::{Delete, DeleteBuilder, DeleteDescriptor};
pub use self::query::{Query, QueryBuilder};
pub use self::read::{Read, ReadBuilder};
pub use self::subscribe::{Subscribe, SubscribeBuilder, SubscribeReply};
pub use self::write::{DelegatedGrant, Write, WriteBuilder, WriteData, WriteProtocol};
pub use crate::data::DataStream;
use crate::{Quota, Range, Result, utils};

// TODO: add builder for RecordsFilter

/// Records filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordsFilter {
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

    /// Whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// Records with the specified context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Records with the specified schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Get a single object by its ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,

    /// The CID of the parent object .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Match records with the specified tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, TagFilter>>,

    /// The MIME type of the requested data. For example, `application/json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_format: Option<String>,

    /// Records with a size within the range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<Range<usize>>,

    /// CID of the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_cid: Option<String>,

    /// Filter messages created within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<Range<DateTime<Utc>>>,

    /// Filter messages published within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<Range<DateTime<Utc>>>,

    /// Match messages updated within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<Range<DateTime<Utc>>>,
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

/// Tag filter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TagFilter {
    /// Match tags starting with a string value.
    StartsWith(String),

    /// Filter tags by range.
    Range(Range<usize>),

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

    /// Add a schema to the filter.
    #[must_use]
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
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
    pub const fn date_created(mut self, date_created: Range<DateTime<Utc>>) -> Self {
        self.date_created = Some(date_created);
        self
    }

    /// Add a date published to the filter.
    #[must_use]
    pub const fn date_published(mut self, date_published: Range<DateTime<Utc>>) -> Self {
        self.date_published = Some(date_published);
        self
    }

    /// Add a date updated to the filter.
    #[must_use]
    pub const fn date_updated(mut self, date_updated: Range<DateTime<Utc>>) -> Self {
        self.date_updated = Some(date_updated);
        self
    }
}
