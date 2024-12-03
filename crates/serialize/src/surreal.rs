//! # Surreal Database

use chrono::{DateTime, SecondsFormat, Utc};
use vercre_dwn::store::{
    MessagesFilter, MessagesQuery, ProtocolsQuery, Query, RecordsFilter, RecordsQuery, TagFilter,
};
use vercre_dwn::{Interface, Method, Quota};

use crate::QuerySerializer;

/// Serialize a supported DWN query to Surreal SQL.
impl QuerySerializer for Query {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        match self {
            Query::Messages(query) => query.serialize(),
            Query::Protocols(query) => query.serialize(),
            Query::Records(query) => query.serialize(),
        }
    }
}

/// Serialize `MessagesQuery` to Surreal SQL.
impl QuerySerializer for MessagesQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = "SELECT * FROM type::table($table) WHERE 1=1 AND".to_string();

        for filter in &self.filters {
            sql.push_str(&format!(" ({filter}) OR", filter = QuerySerializer::serialize(filter)));
        }

        if let Some(stripped) = sql.strip_suffix(" OR") {
            sql = stripped.to_string();
        }
        if let Some(stripped) = sql.strip_suffix(" AND") {
            sql = stripped.to_string();
        }

        sql.push_str(" ORDER BY descriptor.messageTimestamp COLLATE ASC");
        sql
    }
}

/// Serialize `MessagesFilter` to Surreal SQL.
impl QuerySerializer for MessagesFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = String::from("1=1");

        if let Some(interface) = &self.interface {
            sql.push_str(&format!(" AND descriptor.interface='{interface}'"));
        }
        if let Some(method) = &self.method {
            sql.push_str(&format!(" AND descriptor.method='{method}'"));
        }

        // N.B. adding a protocol tag ensures message queries with a protocol
        // filter will return associated grants
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND (descriptor.definition.protocol='{protocol}'"));
            sql.push_str(&format!(" OR descriptor.tags.protocol='{protocol}')"));
        }

        if let Some(timestamp) = &self.message_timestamp {
            let min = &DateTime::<Utc>::MIN_UTC;
            let max = &Utc::now();
            let from =
                timestamp.min.as_ref().unwrap_or(min).to_rfc3339_opts(SecondsFormat::Micros, true);
            let to =
                timestamp.max.as_ref().unwrap_or(max).to_rfc3339_opts(SecondsFormat::Micros, true);
            sql.push_str(&format!(" AND (descriptor.messageTimestamp >= '{from}' AND descriptor.messageTimestamp <='{to}')"));
        }
        sql
    }
}

/// Serialize `ProtocolsQuery` to Surreal SQL.
impl QuerySerializer for ProtocolsQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = format!(
            "SELECT * FROM type::table($table)
            WHERE descriptor.interface='{interface}'
            AND descriptor.method='{method}'",
            interface = Interface::Protocols,
            method = Method::Configure
        );

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND descriptor.definition.protocol='{protocol}'"));
        }

        if let Some(published) = &self.published {
            sql.push_str(&format!(" AND descriptor.definition.published = {published}"));
        }

        sql.push_str(" ORDER BY descriptor.messageTimestamp COLLATE DESC");
        sql
    }
}

/// Serialize `RecordsQuery` to Surreal SQL.
impl QuerySerializer for RecordsQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let min_date = &DateTime::<Utc>::MIN_UTC;
        let max_date = &Utc::now();

        let mut sql = format!(
            "SELECT * FROM type::table($table) WHERE descriptor.interface='{interface}'",
            interface = Interface::Records
        );

        if !self.include_archived {
            sql.push_str(&format!(" AND archived = false"));
        }

        if let Some(method) = &self.method {
            sql.push_str(&format!(" AND descriptor.method='{method}'"));
        }

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!(" AND recordId='{record_id}'"));
        }

        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!(" AND descriptor.parentId='{parent_id}'"));
        }

        if let Some(context_id) = &self.context_id {
            let min_ctx = &"\u{0000}".to_string();
            let max_ctx = &"\u{ffff}".to_string();

            let min = context_id.min.as_ref().unwrap_or(min_ctx);
            let max = context_id.max.as_ref().unwrap_or(max_ctx);
            sql.push_str(&format!(" AND (contextId >= '{min}' AND contextId <= '{max}')"));
        }

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND descriptor.protocol='{protocol}'"));
        }

        if let Some(protocol_path) = &self.protocol_path {
            sql.push_str(&format!(" AND descriptor.protocolPath='{protocol_path}'"));
        }

        if let Some(recipient) = &self.recipient {
            sql.push_str(&quota("descriptor.recipient", recipient));
        }

        if let Some(date_created) = &self.date_created {
            let from = date_created
                .min
                .as_ref()
                .unwrap_or(min_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            let to = date_created
                .max
                .as_ref()
                .unwrap_or(max_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            sql.push_str(&format!(
                " AND (descriptor.dateCreated >= '{from}' AND descriptor.dateCreated <='{to}')"
            ));
        }

        // include `RecordsFilter` sql
        if let Some(filter) = &self.filter {
            sql.push_str(&format!("{}", QuerySerializer::serialize(filter)));
        }

        // sorting
        if let Some(sort) = &self.sort {
            let mut fields = vec![];
            if let Some(dir) = &sort.date_created {
                fields.push(format!(" descriptor.dateCreated COLLATE {dir}"));
            }
            if let Some(dir) = &sort.date_published {
                fields.push(format!(" descriptor.datePublished COLLATE {dir}"));
            }
            if let Some(dir) = &sort.message_timestamp {
                fields.push(format!(" descriptor.messageTimestamp COLLATE {dir}"));
            }
            sql.push_str(&format!(" ORDER BY {sort}", sort = fields.join(",")));
        }

        if let Some(pagination) = &self.pagination {
            if let Some(limit) = pagination.limit {
                sql.push_str(&format!(" LIMIT {limit}"));
            }

            if let Some(offset) = pagination.offset {
                sql.push_str(&format!(" START {offset}"));
            }
        }

        sql
    }
}

/// Serialize `RecordsFilter` to Surreal SQL.
impl QuerySerializer for RecordsFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let min_date = &DateTime::<Utc>::MIN_UTC;
        let max_date = &Utc::now();

        let mut sql = String::new();

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!(" AND recordId='{record_id}'"));
        }
        if let Some(context_id) = &self.context_id {
            sql.push_str(&format!(" AND contextId='{context_id}'"));
        }

        // descriptor fields
        if let Some(recipient) = &self.recipient {
            sql.push_str(&one_or_many("descriptor.recipient", recipient));
        }
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND descriptor.protocol='{protocol}'"));
        }
        if let Some(protocol_path) = &self.protocol_path {
            sql.push_str(&format!(" AND descriptor.protocolPath='{protocol_path}'"));
        }
        if let Some(published) = &self.published {
            sql.push_str(&format!(" AND descriptor.published = {published}"));
        }
        if let Some(schema) = &self.schema {
            sql.push_str(&format!(" AND descriptor.schema='{schema}'"));
        }
        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!(" AND descriptor.parentId='{parent_id}'"));
        }
        if let Some(data_format) = &self.data_format {
            sql.push_str(&format!(" AND descriptor.dataFormat='{data_format}'"));
        }
        if let Some(data_size) = &self.data_size {
            sql.push_str(&format!(
                " AND (descriptor.dataSize >= {min} AND descriptor.dataSize <= {max})",
                min = data_size.min.unwrap_or(0),
                max = data_size.max.unwrap_or(usize::MAX)
            ));
        }
        if let Some(data_cid) = &self.data_cid {
            sql.push_str(&format!(" AND descriptor.dataCid='{data_cid}'"));
        }
        if let Some(date_created) = &self.date_created {
            let from = date_created
                .min
                .as_ref()
                .unwrap_or(min_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            let to = date_created
                .max
                .as_ref()
                .unwrap_or(max_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            sql.push_str(&format!(
                " AND (descriptor.dateCreated >= '{from}' descriptor.dateCreated <= '{to}')"
            ));
        }
        if let Some(date_published) = &self.date_published {
            let from = date_published
                .min
                .as_ref()
                .unwrap_or(min_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            let to = date_published
                .max
                .as_ref()
                .unwrap_or(max_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            sql.push_str(&format!(
                " AND (descriptor.datePublished >= '{from}' AND descriptor.datePublished <='{to}')"
            ));
        }

        // index fields
        if let Some(author) = &self.author {
            sql.push_str(&one_or_many("author", author));
        }
        if let Some(attester) = &self.attester {
            sql.push_str(&format!(" AND attester='{attester}'"));
        }
        if let Some(tags) = &self.tags {
            for (property, filter) in tags {
                sql.push_str(&format!(" AND tags.{property} {}", filter.serialize()));
            }
        }
        if let Some(date_updated) = &self.date_updated {
            let from = date_updated
                .min
                .as_ref()
                .unwrap_or(min_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            let to = date_updated
                .max
                .as_ref()
                .unwrap_or(max_date)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
            sql.push_str(&format!(" AND (dateUpdated >= '{from}' AND dateUpdated <= '{to}')"));
        }

        sql
    }
}

/// Serialize `TagFilter` to Surreal SQL.
impl QuerySerializer for TagFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        match self {
            Self::StartsWith(value) => format!(" LIKE '{value}%'"),
            Self::Range(range) => {
                let min = range.min.unwrap_or(0);
                let max = range.max.unwrap_or(usize::MAX);
                format!(" BETWEEN {min} AND {max}")
            }
            Self::Equal(value) => format!("= '{value}'"),
        }
    }
}

fn one_or_many(field: &str, clause: &Quota<String>) -> String {
    match clause {
        Quota::One(value) => {
            format!(" AND {field}='{value}'")
        }
        Quota::Many(values) => {
            let mut sql = String::new();
            sql.push_str(&format!(" AND {field} IN ("));
            for value in values {
                sql.push_str(&format!("'{value}',"));
            }
            sql.pop(); // remove trailing comma
            sql.push_str(")");
            sql
        }
    }
}

fn quota(field: &str, clause: &Quota<String>) -> String {
    match clause {
        Quota::One(value) => {
            format!(" AND {field}='{value}'")
        }
        Quota::Many(values) => {
            let mut sql = String::new();
            sql.push_str(&format!(" AND {field} IN ("));
            for value in values {
                sql.push_str(&format!("'{value}',"));
            }
            sql.pop(); // remove trailing comma
            sql.push_str(")");
            sql
        }
    }
}
