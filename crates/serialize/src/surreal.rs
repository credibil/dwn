//! # Surreal Database

use chrono::{DateTime, Utc};
use vercre_dwn::store::{
    MessagesFilter, MessagesQuery, ProtocolsQuery, Query, RecordsFilter, RecordsQuery, TagFilter,
};
use vercre_dwn::{Interface, Method, Quota};

use crate::QuerySerializer;

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

impl QuerySerializer for MessagesFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let mut sql = String::from("1=1\n");

        if let Some(interface) = &self.interface {
            sql.push_str(&format!("AND descriptor.interface = '{interface}'\n"));
        }
        if let Some(method) = &self.method {
            sql.push_str(&format!("AND descriptor.method = '{method}'\n"));
        }
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!("AND descriptor.protocol = '{protocol}'\n"));
        }
        if let Some(timestamp) = &self.message_timestamp {
            let min = &DateTime::<Utc>::MIN_UTC.to_rfc3339();
            let max = &Utc::now().to_rfc3339();

            let from = timestamp.min.as_ref().unwrap_or(min);
            let to = timestamp.max.as_ref().unwrap_or(max);
            sql.push_str(&format!("AND descriptor.messageTimestamp BETWEEN '{from}' AND '{to}'\n"));
        }

        sql
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

impl QuerySerializer for RecordsFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        let min_date = &DateTime::<Utc>::MIN_UTC.to_rfc3339();
        let max_date = &Utc::now().to_rfc3339();

        let mut sql = String::new();

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!("AND recordId = '{record_id}'\n"));
        }

        if let Some(context_id) = &self.context_id {
            sql.push_str(&format!("AND contextId = '{context_id}'\n"));
        }

        // descriptor fields
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

        if let Some(schema) = &self.schema {
            sql.push_str(&format!("AND descriptor.schema = '{schema}'\n"));
        }

        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!("AND descriptor.parentId = '{parent_id}'\n"));
        }

        if let Some(data_format) = &self.data_format {
            sql.push_str(&format!("AND descriptor.dataFormat = '{data_format}'\n"));
        }

        if let Some(data_size) = &self.data_size {
            sql.push_str(&format!(
                "descriptor.dataSize BETWEEN {min} AND {max}\n",
                min = data_size.min.unwrap_or(0),
                max = data_size.max.unwrap_or(usize::MAX)
            ));
        }

        if let Some(data_cid) = &self.data_cid {
            sql.push_str(&format!("AND descriptor.dataCid = '{data_cid}'\n"));
        }

        if let Some(date_created) = &self.date_created {
            let from = date_created.min.as_ref().unwrap_or(min_date);
            let to = date_created.max.as_ref().unwrap_or(max_date);
            sql.push_str(&format!("AND descriptor.dateCreated BETWEEN '{from}' AND '{to}'\n"));
        }

        if let Some(date_published) = &self.date_published {
            let from = date_published.min.as_ref().unwrap_or(min_date);
            let to = date_published.max.as_ref().unwrap_or(max_date);
            sql.push_str(&format!("AND descriptor.datePublished BETWEEN '{from}' AND '{to}'\n"));
        }

        // index fields
        if let Some(author) = &self.author {
            sql.push_str(&one_or_many("author", author));
        }

        if let Some(attester) = &self.attester {
            sql.push_str(&format!("AND attester = '{attester}'\n"));
        }

        if let Some(tags) = &self.tags {
            for (property, filter) in tags {
                sql.push_str(&format!("AND tags.{property} {}\n", filter.serialize()));
            }
        }

        if let Some(date_updated) = &self.date_updated {
            let from = date_updated.min.as_ref().unwrap_or(min_date);
            let to = date_updated.max.as_ref().unwrap_or(max_date);
            sql.push_str(&format!("AND dateUpdated BETWEEN '{from}' AND '{to}'\n"));
        }

        sql.pop(); // remove trailing newline
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

impl QuerySerializer for TagFilter {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        match self {
            Self::StartsWith(value) => format!("LIKE '{value}%'"),
            Self::Range(range) => {
                let min = range.min.unwrap_or(0);
                let max = range.max.unwrap_or(usize::MAX);
                format!("BETWEEN {min} AND {max}")
            }
            Self::Equal(value) => format!("= '{value}'"),
        }
    }
}
