//! # Store

use crate::records::RecordsFilter;
use crate::{DateRange, Interface, Method, Quota};

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct RecordsQuery {
    pub record_id: Option<String>,
    pub parent_id: Option<String>,
    pub context_id: Option<String>,
    pub recipient: Option<Quota<String>>,
    pub protocol: Option<String>,
    pub protocol_path: Option<String>,
    pub date_created: Option<DateRange>,
    pub hidden: Option<bool>,
    filter: Option<RecordsFilter>,
}

impl RecordsQuery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hidden: Some(false),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn hidden(mut self, hidden: Option<bool>) -> Self {
        self.hidden = hidden;
        self
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

    #[must_use]
    pub fn date_created(mut self, date_created: DateRange) -> Self {
        self.date_created = Some(date_created);
        self
    }

    pub fn to_sql(self) -> String {
        let mut sql = format!(
            "
            SELECT * FROM message
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'
            ",
            interface = Interface::Records,
            method = Method::Write,
        );

        if let Some(hidden) = &self.hidden {
            sql.push_str(&format!("AND hidden = {hidden}\n"));
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

        if let Some(date_created) = &self.date_created {
            sql.push_str(&format!(
                "AND descriptor.dateCreated BETWEEN {from} AND {to}'\n",
                from = date_created.from,
                to = date_created.to
            ));
        }

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

// let sql = format!("SELECT * FROM {TABLE} {sql}");
// let sql = format!("SELECT * FROM {TABLE} {sql}");

// ----------------------------------------------
// permissions: fetch grant
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{grant_id}'
//     AND hidden = false
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
// );

// ----------------------------------------------
// grant: grant revoked
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.parentId = '{parent_id}'
//     AND descriptor.protocolPath = '{REVOCATION_PATH}'
//     AND queryable = true
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     parent_id = self.id
// );

// ----------------------------------------------
// protocol: write parent (verify protocol path)
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.protocol = '{protocol}'
//     AND recordId = '{parent_id}'
//     AND queryable = true
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
// );

// ----------------------------------------------
// protocol: verify write role integrity
// ----------------------------------------------
// context =
//     format!("AND contextId BETWEEN '{parent_context}' AND '{parent_context}\u{ffff}'");

// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.protocol = '{protocol}'
//     AND descriptor.protocolPath = '{protocol_path}'
//     AND descriptor.recipient = '{recipient}'
//     AND queryable = true
//     {context}
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
// );

// ----------------------------------------------
// protocol: verify invoked role
// ----------------------------------------------
// `context_id` prefix filter
// let context_prefix = if segment_count > 0 {
//     // context_id segment count is never shorter than the role path count.
//     let context_id = context_id.unwrap_or_default();
//     let context_id_segments: Vec<&str> = context_id.split('/').collect();
//     let prefix = context_id_segments[..segment_count].join("/");
//     format!("AND contextId BETWEEN '{prefix}' AND '{prefix}\u{ffff}'")
// } else {
//     String::new()
// };

// // fetch the invoked role record
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.protocol = '{protocol}'
//     AND descriptor.protocolPath = '{protocol_role}'
//     AND descriptor.recipient = '{author}'
//     {context_prefix}
//     AND queryable = true
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
// );

// ----------------------------------------------
// protocol: protocol definition
// ----------------------------------------------
// // fetch the corresponding protocol definition
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.definition.protocol = '{protocol_uri}'
//     ",
//     interface = Interface::Protocols,
//     method = Method::Configure,
// );

// ----------------------------------------------
// protocols: query (fetch config)
// ----------------------------------------------
// if let Some(filter) = filter {
//     let protocol_uri = utils::clean_url(&filter.protocol)?;
//     protocol = format!("AND descriptor.definition.protocol = '{protocol_uri}'");
// };

// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.definition.published = true
//     {protocol}
//     ",
//     interface = Interface::Protocols,
//     method = Method::Configure,
// );

// ----------------------------------------------
// messages: query
// ----------------------------------------------
// let sql = format!(
//     "
//     {filter_sql}
//     ORDER BY descriptor.messageTimestamp ASC
//     "
// );

// ----------------------------------------------
// records: delete > query
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{record_id}'
//     AND hidden = false
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     record_id = delete.descriptor.record_id,
// );

// ----------------------------------------------
// records: delete > check latest before delete
// ----------------------------------------------
// // get the latest active `RecordsWrite` and `RecordsDelete` messages
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{record_id}'
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     record_id = delete.descriptor.record_id,
// );

// ----------------------------------------------
// records: delete > purge descendants
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND descriptor.parentId = '{record_id}'
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,

// );

// ----------------------------------------------
// records: query
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     {filter_sql}
//     AND hidden = false
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     filter_sql = filter.to_sql(),
// );

// ----------------------------------------------
// records: query
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{record_id}'
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     record_id = &write.record_id,
//     // AND hidden = false
// );

// ----------------------------------------------
// records: read > query
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     {filter_sql}
//     AND hidden = false
//     ORDER BY descriptor.messageTimestamp DESC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     filter_sql = read.descriptor.filter.to_sql(),
// );

// ----------------------------------------------
// records: read > initial write
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{record_id}'
//     AND hidden = true
//     ORDER BY descriptor.messageTimestamp ASC
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
//     record_id = write.record_id,
// );

// ----------------------------------------------
// records: write > exiting entries
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND recordId = '{record_id}'
//     ORDER BY descriptor.messageTimestamp ASC
//     ",
//     interface = Interface::Records,
// );

// ----------------------------------------------
// records: write > revoke grants
// ----------------------------------------------
// let sql = format!(
//     "
//     WHERE descriptor.interface = '{interface}'
//     AND descriptor.method = '{method}'
//     AND recordId = '{grant_id}'
//     AND dateCreated >= '{message_timestamp}
//     AND hidden = false
//     ",
//     interface = Interface::Records,
//     method = Method::Write,
// );
