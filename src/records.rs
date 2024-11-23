//! # Records

pub mod delete;
pub mod query;
pub mod read;
pub mod subscribe;
pub mod write;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::delete::{Delete, DeleteBuilder};
pub use self::query::{Query, QueryBuilder};
pub use self::read::{Read, ReadBuilder};
pub use self::subscribe::{Subscribe, SubscribeBuilder, SubscribeReply};
pub(crate) use self::write::{earliest_and_latest, existing_entries};
pub use self::write::{DelegatedGrant, Write, WriteBuilder, WriteData, WriteProtocol};
pub use crate::data::DataStream;
use crate::{utils, Quota, Range, Result};

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
    pub date_created: Option<Range<String>>,

    /// Filter messages published within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<Range<String>>,

    /// Match messages updated within the specified range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<Range<String>>,
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
