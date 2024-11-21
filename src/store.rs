//! # Store

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::endpoint::Message;
use crate::records::RecordsFilter;
use crate::{protocols, records, Descriptor, Interface, Method, Quota, Result};

/// Wraps each message with a unifying type used in operations common to all
/// messages. For example, storing and retrieving from the `MessageStore`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Record {
    /// The message type.
    #[serde(flatten)]
    pub message: RecordType,

    /// Indexed message object fields, flattened for querying.
    #[serde(flatten)]
    #[serde(skip_deserializing)]
    pub indexes: Map<String, Value>,
}

impl Record {
    /// The message's CID.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn cid(&self) -> Result<String> {
        match self.message {
            RecordType::Write(ref write) => write.cid(),
            RecordType::Delete(ref delete) => delete.cid(),
            RecordType::Configure(ref configure) => configure.cid(),
        }
    }

    /// The message's CID.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor {
        match self.message {
            RecordType::Write(ref write) => write.descriptor(),
            RecordType::Delete(ref delete) => delete.descriptor(),
            RecordType::Configure(ref configure) => configure.descriptor(),
        }
    }
}

impl Record {
    /// Return the `RecordsWrite` message, if set.
    #[must_use]
    pub const fn as_write(&self) -> Option<&records::Write> {
        match &self.message {
            RecordType::Write(write) => Some(write),
            _ => None,
        }
    }

    /// Return the `RecordsDelete` message, if set.
    #[must_use]
    pub const fn as_delete(&self) -> Option<&records::Delete> {
        match &self.message {
            RecordType::Delete(delete) => Some(delete),
            _ => None,
        }
    }

    /// Return the `ProtocolsConfigure` message, if set.
    #[must_use]
    pub const fn as_configure(&self) -> Option<&protocols::Configure> {
        match &self.message {
            RecordType::Configure(configure) => Some(configure),
            _ => None,
        }
    }
}

impl Deref for Record {
    type Target = RecordType;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// Records read message payload
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[allow(missing_docs)]
pub enum RecordType {
    Write(records::Write),
    Delete(records::Delete),
    Configure(protocols::Configure),
}

impl Default for RecordType {
    fn default() -> Self {
        Self::Write(records::Write::default())
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub(crate) struct RecordsQuery {
    pub record_id: Option<String>,
    pub parent_id: Option<String>,
    pub context_id: Option<String>,
    pub recipient: Option<Quota<String>>,
    pub protocol: Option<String>,
    pub protocol_path: Option<String>,
    // pub date_created: Option<DateRange>,
    pub hidden: Option<bool>,
    pub method: Option<Method>,
    filter: Option<RecordsFilter>,
}

impl RecordsQuery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            method: Some(Method::Write),
            hidden: Some(false),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    #[must_use]
    pub fn parent_id(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    // TODO: support LT, GT, and BETWEEN for context
    #[must_use]
    pub fn context_id(mut self, context_id: impl Into<String>) -> Self {
        self.context_id = Some(context_id.into());
        self
    }

    #[must_use]
    pub fn add_recipient(mut self, recipient: impl Into<String>) -> Self {
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
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    #[must_use]
    pub fn protocol_path(mut self, protocol_path: impl Into<String>) -> Self {
        self.protocol_path = Some(protocol_path.into());
        self
    }

    // #[must_use]
    // pub fn date_created(mut self, date_created: DateRange) -> Self {
    //     self.date_created = Some(date_created);
    //     self
    // }

    #[must_use]
    pub fn method(mut self, method: Option<Method>) -> Self {
        self.method = method;
        self
    }

    #[must_use]
    pub fn hidden(mut self, hidden: Option<bool>) -> Self {
        self.hidden = hidden;
        self
    }

    pub fn to_sql(self) -> String {
        let mut sql = format!(
            "
            SELECT * FROM message
            WHERE descriptor.interface = '{interface}'
            ",
            interface = Interface::Records
        );

        if let Some(hidden) = &self.hidden {
            sql.push_str(&format!("AND hidden = {hidden}\n"));
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
            sql.push_str(&format!("AND contextId = '{context_id}'\n"));
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

        // if let Some(date_created) = &self.date_created {
        //     sql.push_str(&format!(
        //         "AND descriptor.dateCreated BETWEEN {from} AND {to}'\n",
        //         from = date_created.from,
        //         to = date_created.to
        //     ));
        // }

        if let Some(filter) = &self.filter {
            sql.push_str(&format!("{}\n", filter.to_sql()));
        }

        sql.push_str("ORDER BY descriptor.messageTimestamp DESC");
        sql
    }
}

impl From<RecordsFilter> for RecordsQuery {
    fn from(filter: RecordsFilter) -> Self {
        let mut sql = Self::new();
        sql.filter = Some(filter);
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
