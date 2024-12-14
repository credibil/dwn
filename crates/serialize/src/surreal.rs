//! # Surreal Database

use vercre_dwn::store::{
    Lower, MessagesFilter, MessagesQuery, ProtocolsQuery, Query, RecordsFilter, RecordsQuery, Sort,
    TagFilter, Upper,
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
        let mut sql = "SELECT * FROM type::table($table) WHERE 1=1".to_string();

        if !self.filters.is_empty() {
            sql.push_str(" AND (");
            for filter in &self.filters {
                sql.push_str(&format!(
                    " ({filter}) OR",
                    filter = QuerySerializer::serialize(filter)
                ));
            }
            if let Some(stripped) = sql.strip_suffix(" OR") {
                sql = stripped.to_string();
            }
            sql.push_str(")");
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
            sql.push_str(&format!(" AND (descriptor.definition.protocol = '{protocol}'"));
            sql.push_str(&format!(" OR descriptor.tags.protocol = '{protocol}')"));
        }

        if let Some(ts_range) = &self.message_timestamp {
            sql.push_str(" AND (");
            let and = if ts_range.upper.is_some() { " AND " } else { "" };

            match ts_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    sql.push_str(&format!("descriptor.messageTimestamp > '{lower}'{and}"));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    sql.push_str(&format!("descriptor.messageTimestamp >= '{lower}'{and}"));
                }
                None => {}
            }
            match ts_range.upper {
                Some(Upper::LessThan(upper)) => {
                    sql.push_str(&format!("descriptor.messageTimestamp < '{upper}'"));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    sql.push_str(&format!("descriptor.messageTimestamp <= '{upper}'"));
                }
                None => {}
            }

            sql.push_str(")");
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
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'",
            interface = Interface::Protocols,
            method = Method::Configure
        );

        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND descriptor.definition.protocol = '{protocol}'"));
        }

        if let Some(published) = &self.published {
            if *published {
                sql.push_str(" AND descriptor.definition.published = true");
            } else {
                sql.push_str(" AND (!descriptor.published OR descriptor.published = false)");
            }
        }

        sql.push_str(" ORDER BY descriptor.messageTimestamp COLLATE ASC");
        sql
    }
}

/// Serialize `RecordsQuery` to Surreal SQL.
impl QuerySerializer for RecordsQuery {
    type Output = String;

    fn serialize(&self) -> Self::Output {
        // let min_date = &DateTime::<Utc>::MIN_UTC;
        // let max_date = &Utc::now();

        let mut sql = format!(
            "SELECT * FROM type::table($table) WHERE descriptor.interface = '{interface}'",
            interface = Interface::Records
        );

        if !self.include_archived {
            sql.push_str(" AND (!archived OR archived = false)");
        }
        if let Some(method) = &self.method {
            sql.push_str(&format!(" AND descriptor.method = '{method}'"));
        }

        if !self.filters.is_empty() {
            sql.push_str(" AND (");
            for filter in &self.filters {
                sql.push_str(&format!(
                    " ({filter}) OR",
                    filter = QuerySerializer::serialize(filter)
                ));
            }
            if let Some(stripped) = sql.strip_suffix(" OR") {
                sql = stripped.to_string();
            }
            sql.push_str(")");
        }

        // sorting
        if let Some(sort) = &self.sort {
            match sort {
                Sort::CreatedAscending | Sort::PublishedAscending | Sort::TimestampAscending => {
                    sql.push_str(&format!(" ORDER BY descriptor.{sort} COLLATE ASC"));
                }
                Sort::CreatedDescending | Sort::PublishedDescending | Sort::TimestampDescending => {
                    sql.push_str(&format!(" ORDER BY descriptor.{sort} COLLATE DESC"));
                }
            }
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
        let mut sql = String::from("1=1");

        if let Some(record_id) = &self.record_id {
            sql.push_str(&format!(" AND recordId = '{record_id}'"));
        }
        if let Some(parent_id) = &self.parent_id {
            sql.push_str(&format!(" AND descriptor.parentId = '{parent_id}'"));
        }
        // if let Some(context_id) = &self.context_id {
        //     sql.push_str(&format!(" AND contextId = '{context_id}'"));
        // }
        if let Some(context_id) = &self.context_id {
            // let min_ctx = &"\u{0000}".to_string();
            // let max_ctx = &"\u{ffff}".to_string();
            // let min = context_id.min.as_ref().unwrap_or(min_ctx);
            // let max = context_id.max.as_ref().unwrap_or(max_ctx);

            sql.push_str(&format!(
                " AND (contextId >= '{context_id}' AND contextId <= '{context_id}\u{ffff}')"
            ));
        }

        // descriptor fields
        if let Some(recipient) = &self.recipient {
            sql.push_str(&one_or_many("descriptor.recipient", recipient));
        }
        if let Some(protocol) = &self.protocol {
            sql.push_str(&format!(" AND descriptor.protocol = '{protocol}'"));
        }
        if let Some(protocol_path) = &self.protocol_path {
            sql.push_str(&format!(" AND descriptor.protocolPath = '{protocol_path}'"));
        }
        if let Some(published) = &self.published {
            if *published {
                sql.push_str(&format!(" AND descriptor.published = true"));
            } else {
                sql.push_str(&format!(
                    " AND (!descriptor.published OR descriptor.published = false)"
                ));
            }
        }
        if let Some(schema) = &self.schema {
            sql.push_str(&format!(" AND descriptor.schema = '{schema}'"));
        }

        if let Some(data_format) = &self.data_format {
            sql.push_str(&format!(" AND descriptor.dataFormat = '{data_format}'"));
        }
        if let Some(size_range) = &self.data_size {
            sql.push_str(" AND (");
            let and = if size_range.upper.is_some() { " AND " } else { "" };

            match size_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    sql.push_str(&format!("descriptor.dataSize > {lower}{and}"));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    sql.push_str(&format!("descriptor.dataSize >= {lower}{and}"));
                }
                None => {}
            }
            match size_range.upper {
                Some(Upper::LessThan(upper)) => {
                    sql.push_str(&format!("descriptor.dataSize < {upper}"));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    sql.push_str(&format!("descriptor.dataSize <= {upper}"));
                }
                None => {}
            }

            sql.push_str(")");
        }
        if let Some(data_cid) = &self.data_cid {
            sql.push_str(&format!(" AND descriptor.dataCid = '{data_cid}'"));
        }
        if let Some(ts_range) = &self.date_created {
            sql.push_str(" AND (");
            let and = if ts_range.upper.is_some() { " AND " } else { "" };

            match ts_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    sql.push_str(&format!("descriptor.dateCreated > '{lower}'{and}"));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    sql.push_str(&format!("descriptor.dateCreated >= '{lower}'{and}"));
                }
                None => {}
            }
            match ts_range.upper {
                Some(Upper::LessThan(upper)) => {
                    sql.push_str(&format!("descriptor.dateCreated < '{upper}'"));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    sql.push_str(&format!("descriptor.dateCreated <= '{upper}'"));
                }
                None => {}
            }

            sql.push_str(")");
        }

        if let Some(ts_range) = &self.date_published {
            sql.push_str(" AND (");
            let and = if ts_range.upper.is_some() { " AND " } else { "" };

            match ts_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    sql.push_str(&format!("descriptor.datePublished > '{lower}'{and}"));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    sql.push_str(&format!("descriptor.datePublished >= '{lower}'{and}"));
                }
                None => {}
            }
            match ts_range.upper {
                Some(Upper::LessThan(upper)) => {
                    sql.push_str(&format!("descriptor.datePublished < '{upper}'"));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    sql.push_str(&format!("descriptor.datePublished <= '{upper}'"));
                }
                None => {}
            }

            sql.push_str(")");
        }

        // index fields
        if let Some(author) = &self.author {
            sql.push_str(&one_or_many("author", author));
        }
        if let Some(attester) = &self.attester {
            sql.push_str(&format!(" AND attester = '{attester}'"));
        }
        if let Some(tags) = &self.tags {
            for (property, filter) in tags {
                sql.push_str(&format!(" AND tags.{property} {}", filter.serialize()));
            }
        }
        if let Some(ts_range) = &self.date_updated {
            sql.push_str(" AND (");
            let and = if ts_range.upper.is_some() { " AND " } else { "" };

            match ts_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    sql.push_str(&format!("descriptor.dateUpdated > '{lower}'{and}"));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    sql.push_str(&format!("descriptor.dateUpdated >= '{lower}'{and}"));
                }
                None => {}
            }
            match ts_range.upper {
                Some(Upper::LessThan(upper)) => {
                    sql.push_str(&format!("descriptor.dateUpdated < '{upper}'"));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    sql.push_str(&format!("descriptor.dateUpdated <= '{upper}'"));
                }
                None => {}
            }
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
                let mut sql = String::new();
                let and = if range.upper.is_some() { " AND " } else { "" };

                match range.lower {
                    Some(Lower::GreaterThan(lower)) => {
                        sql.push_str(&format!("descriptor.dateUpdated > '{lower}'{and}"));
                    }
                    Some(Lower::GreaterThanOrEqual(lower)) => {
                        sql.push_str(&format!("descriptor.dateUpdated >= '{lower}'{and}"));
                    }
                    None => {}
                }
                match range.upper {
                    Some(Upper::LessThan(upper)) => {
                        sql.push_str(&format!("descriptor.dateUpdated < '{upper}'"));
                    }
                    Some(Upper::LessThanOrEqual(upper)) => {
                        sql.push_str(&format!("descriptor.dateUpdated <= '{upper}'"));
                    }
                    None => {}
                }

                sql
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
            // Check whether any value in an array equals another value.
            // SELECT * FROM {field} ?= {value};

            let mut sql = String::new();
            sql.push_str(&format!(" AND (1=1"));
            for value in values {
                sql.push_str(&format!(" OR {field}='{value}'"));
            }
            sql.push_str(")");
            sql
        }
    }
}
