//! # Messages
//!
//! Decentralized Web Node messaging framework.

pub(crate) mod protocol;
pub mod read;
pub mod write;

use std::collections::BTreeMap;

use anyhow::Result;
pub use read::{Read, ReadBuilder, ReadReply};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub(crate) use write::{existing_entries, first_and_last};
pub use write::{
    DelegatedGrant, Write, WriteBuilder, WriteData, WriteDescriptor, WriteProtocol, WriteReply,
};

use crate::auth::Authorization;
use crate::{utils, DateRange, Descriptor, Pagination, Quota};

/// Records Query payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// Records Subscribe payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// Records Delete payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Delete {
    /// The Subscribe descriptor.
    pub descriptor: DeleteDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    pub filter: RecordsFilter,

    /// The pagination cursor.
    pub pagination: Option<Pagination>,
}

/// Read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Record CID.
    pub filter: RecordsFilter,
}

/// Suscribe descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records to subscribe to.
    pub filter: RecordsFilter,
}

/// Read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Record CID.
    pub record_id: String,

    /// Purge any descendent records should?
    pub prune: bool,
}

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

    /// Record matching the specified protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Record protocol path.
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
    pub data_size: Option<SizeRange>,

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

    pub(crate) fn to_sql(&self) -> String {
        let mut sql = String::new();

        if let Some(author) = &self.author {
            sql.push_str(&one_or_many("author", author));
        }

        if let Some(attester) = &self.attester {
            sql.push_str(&format!("AND attester = '{attester}'\n"));
        }

        if let Some(recipient) = &self.recipient {
            sql.push_str(&one_or_many("descriptor.recipient", recipient));
        }

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND descriptor.protocol = '{protocol}'\n"));
        }

        if let Some(protocol_path) = &self.protocol_path {
            sql.push_str(&format!("AND descriptor.protocolPath = '{protocol_path}'\n"));
        }

        if let Some(published) = &self.published {
            sql.push_str(&format!("AND descriptor.published = {published}\n"));
        }

        if let Some(context_id) = &self.context_id {
            sql.push_str(&format!("AND contextId = '{context_id}'\n"));
        }

        if let Some(schema) = &self.schema {
            sql.push_str(&format!("AND descriptor.schema = '{schema}'\n"));
        }

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!("AND recordId = '{record_id}'\n"));
        }

        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!("AND descriptor.parentId = '{parent_id}'\n"));
        }

        if let Some(tags) = &self.tags {
            for (property, filter) in tags {
                sql.push_str(&format!("AND descriptor.tags.{property} {}\n", filter.to_sql()));
            }
        }

        if let Some(data_format) = &self.data_format {
            sql.push_str(&format!("AND descriptor.dataFormat = '{data_format}'\n"));
        }

        if let Some(data_size) = &self.data_size {
            sql.push_str(&format!(
                "descriptor.dataSize BETWEEN {min} AND {max}\n",
                min = data_size.min.unwrap_or(0),
                max = data_size.max.unwrap_or(u64::MAX)
            ));
        }

        if let Some(data_cid) = &self.data_cid {
            sql.push_str(&format!("AND descriptor.dataCid = '{data_cid}'\n"));
        }

        if let Some(date_created) = &self.date_created {
            sql.push_str(&format!(
                "AND descriptor.dateCreated BETWEEN {from} AND {to}'\n",
                from = date_created.from,
                to = date_created.to
            ));
        }

        if let Some(date_published) = &self.date_published {
            sql.push_str(&format!(
                "AND descriptor.datePublished BETWEEN {from} AND {to}'\n",
                from = date_published.from,
                to = date_published.to
            ));
        }

        if let Some(date_updated) = &self.date_updated {
            sql.push_str(&format!(
                "AND descriptor.dateUpdated BETWEEN {from} AND {to}'\n",
                from = date_updated.from,
                to = date_updated.to
            ));
        }

        sql
    }
}

fn one_or_many(field: &str, clause: &Quota<String>) -> String {
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

/// Tag filter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TagFilter {
    /// Match tags starting with a string value.
    StartsWith(String),

    /// Filter tags by range.
    Range(SizeRange),

    /// Filter by a specific value.
    Equal(Value),
}

impl TagFilter {
    pub(crate) fn to_sql(&self) -> String {
        match self {
            Self::StartsWith(value) => format!("LIKE '{value}%'"),
            Self::Range(range) => {
                let min = range.min.unwrap_or(0);
                let max = range.max.unwrap_or(u64::MAX);
                format!("BETWEEN {min} AND {max}")
            }
            Self::Equal(value) => format!("= '{value}'"),
        }
    }
}

impl Default for TagFilter {
    fn default() -> Self {
        Self::Equal(Value::Null)
    }
}

/// Size range.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeRange {
    /// The minimum size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,

    /// The maximum size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
}
