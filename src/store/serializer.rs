//! # Serializer
//!
//! Serializer is used by DWN to generate queries native to the database(s).

use std::collections::BTreeMap;

use anyhow::Result;

use crate::records::DateRange;
use crate::store::{
    Lower, MessagesFilter, MessagesQuery, ProtocolsQuery, Query, RecordsFilter, RecordsQuery, Sort,
    TagFilter, Upper,
};
use crate::{Interface, Method, Quota};

/// Serializer is used by DWN to generate queries native to the database(s)
/// selected when implementing a DWN node.
///
/// The `Serializer` trait is intended to be used to generate one or more query
/// clauses concatenated using AND/OR conjunctions. In turn a clause may can
/// contain one or more conditions concatenated using an AND/OR conjunction.
///
/// A condition consists of a field, operator, and value.
pub trait Serializer {
    /// The type of clause used by the serializer.
    type Clause: Clause;

    /// Creates a new query clause that uses an OR conjunction to join clause
    /// conditions.
    fn or_clause(&mut self) -> &mut Self::Clause;

    /// Creates a new query clause that uses an AND conjunction to join clause
    /// conditions.
    fn and_clause(&mut self) -> &mut Self::Clause;

    /// Sets an ordering clause to use for query results.
    fn order(&mut self, field: &str, sort: Dir);

    /// Sets a limit and offset to limit the number of results returned.
    fn limit(&mut self, limit: usize, offset: usize);
}

/// A `Clause` is used to generate a query clause contain one or more conditions.
pub trait Clause: Serializer {
    /// Adds a condition to the clause.
    fn condition(&mut self, field: &str, op: Op, value: Value);

    /// Closes the clause.
    fn close(&mut self);
}

/// A `Value` is used to represent a condition value.
pub enum Value<'a> {
    /// A boolean value.
    Bool(bool),

    /// An integer value.
    Int(usize),

    /// A string value.
    Str(&'a str),
}

/// An `Op` is used to represent a condition operator.
pub enum Op {
    /// Equal to.
    Eq,

    /// Greater than.
    Gt,

    /// Greater than or equal to.
    Ge,

    /// Less than.
    Lt,

    /// Less than or equal to.
    Le,

    /// Like.
    Like,
}

/// A `Dir` is used to represent a sort direction.
pub enum Dir {
    /// Sort ascending.
    Asc,

    /// Sort descending.
    Desc,
}

/// `Serialize` is used to provide overridable query serialization.
pub trait Serialize {
    /// Serialize a DWN query using the given `Serializer`.
    ///
    /// # Errors
    /// LATER: Add errors
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()>;
}

/// Serialize a supported DWN query to Surreal SQL.
impl Serialize for Query {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        match self {
            Self::Messages(query) => query.serialize(serializer),
            Self::Protocols(query) => query.serialize(serializer),
            Self::Records(query) => query.serialize(serializer),
        }
    }
}

/// Serialize `ProtocolsQuery`.
impl Serialize for ProtocolsQuery {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        let outer_and = serializer.and_clause();
        outer_and.condition(
            "descriptor.interface",
            Op::Eq,
            Value::Str(&Interface::Protocols.to_string()),
        );
        outer_and.condition(
            "descriptor.method",
            Op::Eq,
            Value::Str(&Method::Configure.to_string()),
        );

        if let Some(protocol) = &self.protocol {
            outer_and.condition("descriptor.definition.protocol", Op::Eq, Value::Str(protocol));
        }
        if let Some(published) = &self.published {
            outer_and.condition("descriptor.definition.published", Op::Eq, Value::Bool(*published));
        }
        outer_and.close();

        serializer.order("descriptor.messageTimestamp", Dir::Asc);

        Ok(())
    }
}

/// Serialize `MessagesQuery`.
impl Serialize for MessagesQuery {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        if !self.filters.is_empty() {
            let outer_or = serializer.or_clause();
            for filter in &self.filters {
                filter.serialize(outer_or)?;
            }
            outer_or.close();
        }

        serializer.order("descriptor.messageTimestamp", Dir::Asc);

        Ok(())
    }
}
impl Serialize for MessagesFilter {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        let outer_and = serializer.and_clause();

        if let Some(interface) = &self.interface {
            outer_and.condition("descriptor.interface", Op::Eq, Value::Str(&interface.to_string()));
        }
        if let Some(method) = &self.method {
            outer_and.condition("descriptor.method", Op::Eq, Value::Str(&method.to_string()));
        }

        if let Some(protocol) = &self.protocol {
            let protocol_or = outer_and.or_clause();
            protocol_or.condition("descriptor.definition.protocol", Op::Eq, Value::Str(protocol));

            // adding protocol tag will return grants with the same protocol
            protocol_or.condition("descriptor.tags.protocol", Op::Eq, Value::Str(protocol));
            protocol_or.close();
        }

        if let Some(ts_range) = &self.message_timestamp {
            let field = "descriptor.messageTimestamp";
            let range_and = outer_and.and_clause();
            match ts_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    range_and.condition(field, Op::Gt, Value::Str(&lower.to_string()));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    range_and.condition(field, Op::Ge, Value::Str(&lower.to_string()));
                }
                None => {}
            }
            match ts_range.upper {
                Some(Upper::LessThan(upper)) => {
                    range_and.condition(field, Op::Lt, Value::Str(&upper.to_string()));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    range_and.condition(field, Op::Le, Value::Str(&upper.to_string()));
                }
                None => {}
            }
            range_and.close();
        }

        outer_and.close();
        Ok(())
    }
}

/// Serialize `RecordsQuery` to Surreal SQL.
impl Serialize for RecordsQuery {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        let outer_and = serializer.and_clause();

        outer_and.condition(
            "descriptor.interface",
            Op::Eq,
            Value::Str(&Interface::Records.to_string()),
        );

        if let Some(method) = &self.method {
            outer_and.condition("descriptor.method", Op::Eq, Value::Str(&method.to_string()));
        }
        if !self.include_archived {
            outer_and.condition("archived", Op::Eq, Value::Bool(false));
        }

        if !self.filters.is_empty() {
            let filters_or = outer_and.or_clause();
            for filter in &self.filters {
                filter.serialize(filters_or)?;
            }
            filters_or.close();
        }

        outer_and.close();

        // sorting
        if let Some(sort) = &self.sort {
            match sort {
                Sort::CreatedAscending | Sort::PublishedAscending | Sort::TimestampAscending => {
                    serializer.order(&format!("descriptor.{sort}"), Dir::Asc);
                }
                Sort::CreatedDescending | Sort::PublishedDescending | Sort::TimestampDescending => {
                    serializer.order(&format!("descriptor.{sort}"), Dir::Desc);
                }
            }
        }

        // FIXME: pagination
        if let Some(pagination) = &self.pagination {
            serializer
                .limit(pagination.limit.unwrap_or_default(), pagination.offset.unwrap_or_default());
        }

        Ok(())
    }
}

/// Serialize `RecordsFilter` to Surreal SQL.
impl Serialize for RecordsFilter {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        let outer_and = serializer.and_clause();

        if let Some(record_id) = &self.record_id {
            outer_and.condition("recordId", Op::Eq, Value::Str(record_id));
        }
        if let Some(parent_id) = &self.parent_id {
            outer_and.condition("descriptor.parentId", Op::Eq, Value::Str(parent_id));
        }
        if let Some(context_id) = &self.context_id {
            // let min_ctx = &"\u{0000}".to_string();
            let range_and = outer_and.and_clause();
            range_and.condition("contextId", Op::Ge, Value::Str(context_id));
            range_and.condition("contextId", Op::Le, Value::Str(&format!("{context_id}\u{ffff}")));
            range_and.close();
        }

        // descriptor fields
        if let Some(recipient) = &self.recipient {
            match recipient {
                Quota::One(recipient) => {
                    outer_and.condition("descriptor.recipient", Op::Eq, Value::Str(recipient));
                }
                Quota::Many(recipients) => {
                    let many_and = outer_and.or_clause();
                    for recipient in recipients {
                        many_and.condition("descriptor.recipient", Op::Eq, Value::Str(recipient));
                    }
                    many_and.close();
                }
            }
        }
        if let Some(protocol) = &self.protocol {
            outer_and.condition("descriptor.protocol", Op::Eq, Value::Str(protocol));
        }
        if let Some(protocol_path) = &self.protocol_path {
            outer_and.condition("descriptor.protocolPath", Op::Eq, Value::Str(protocol_path));
        }
        if let Some(published) = &self.published {
            outer_and.condition("descriptor.published", Op::Eq, Value::Bool(*published));
        }
        if let Some(schema) = &self.schema {
            outer_and.condition("descriptor.schema", Op::Eq, Value::Str(schema));
        }

        if let Some(data_format) = &self.data_format {
            outer_and.condition("descriptor.dataFormat", Op::Eq, Value::Str(data_format));
        }
        if let Some(size_range) = &self.data_size {
            let field = "descriptor.dataSize";
            let range_and = outer_and.and_clause();
            match size_range.lower {
                Some(Lower::GreaterThan(lower)) => {
                    range_and.condition(field, Op::Gt, Value::Int(lower));
                }
                Some(Lower::GreaterThanOrEqual(lower)) => {
                    range_and.condition(field, Op::Ge, Value::Int(lower));
                }
                None => {}
            }
            match size_range.upper {
                Some(Upper::LessThan(upper)) => {
                    range_and.condition(field, Op::Lt, Value::Int(upper));
                }
                Some(Upper::LessThanOrEqual(upper)) => {
                    range_and.condition(field, Op::Le, Value::Int(upper));
                }
                None => {}
            }
            range_and.close();
        }
        if let Some(data_cid) = &self.data_cid {
            outer_and.condition("descriptor.dataCid", Op::Eq, Value::Str(data_cid));
        }
        if let Some(date_range) = &self.date_created {
            serialize_date_range("descriptor.dateCreated", date_range, outer_and);
        }
        if let Some(date_range) = &self.date_published {
            serialize_date_range("descriptor.datePublished", date_range, outer_and);
        }
        if let Some(date_range) = &self.date_updated {
            // N.B. `dateUpdated` is set in the Write record's auxilary indexes in `store.rs`
            // serialize_date_range("dateUpdated", date_range, outer_and);
            serialize_date_range("descriptor.messageTimestamp", date_range, outer_and);
        }

        // index fields
        if let Some(author) = &self.author {
            match author {
                Quota::One(author) => {
                    outer_and.condition("author", Op::Eq, Value::Str(author));
                }
                Quota::Many(authors) => {
                    let many_and = outer_and.or_clause();
                    for author in authors {
                        many_and.condition("author", Op::Eq, Value::Str(author));
                    }
                    many_and.close();
                }
            }
        }
        if let Some(attester) = &self.attester {
            outer_and.condition("attester", Op::Eq, Value::Str(attester));
        }

        if let Some(tags) = &self.tags {
            serialize_tags(tags, outer_and);
        }

        outer_and.close();
        Ok(())
    }
}

fn serialize_date_range<S: Serializer>(field: &str, date_range: &DateRange, serializer: &mut S) {
    let range_and = serializer.and_clause();
    if let Some(lower) = date_range.lower {
        range_and.condition(field, Op::Gt, Value::Str(&lower.to_string()));
    }
    if let Some(upper) = date_range.upper {
        range_and.condition(field, Op::Lt, Value::Str(&upper.to_string()));
    }
    range_and.close();
}

fn serialize_tags<S: Serializer>(tags: &BTreeMap<String, TagFilter>, serializer: &mut S) {
    let tags_and = serializer.and_clause();
    for (property, filter) in tags {
        let field = &format!("tags.{property}");

        match filter {
            TagFilter::StartsWith(value) => {
                tags_and.condition(field, Op::Like, Value::Str(&format!("{value}%")));
            }
            TagFilter::Equal(_value) => {
                // FIXME: match value type
                //tags_and.condition(field, Op::Eq, Value::Str(value))
            }
            TagFilter::Range(range) => {
                let range_and = tags_and.and_clause();
                match range.lower {
                    Some(Lower::GreaterThan(lower)) => {
                        range_and.condition(field, Op::Gt, Value::Int(lower));
                    }
                    Some(Lower::GreaterThanOrEqual(lower)) => {
                        range_and.condition(field, Op::Ge, Value::Int(lower));
                    }
                    None => {}
                }
                match range.upper {
                    Some(Upper::LessThan(upper)) => {
                        range_and.condition(field, Op::Lt, Value::Int(upper));
                    }
                    Some(Upper::LessThanOrEqual(upper)) => {
                        range_and.condition(field, Op::Le, Value::Int(upper));
                    }
                    None => {}
                }
                range_and.close();
            }
        }
    }
    tags_and.close();
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_serialize() {
        let query = Query::Protocols(ProtocolsQuery {
            protocol: Some("dwn".to_string()),
            published: Some(false),
            // published: None,
        });

        let mut serializer = Sql::new();

        query.serialize(&mut serializer).unwrap();
        println!("{}", serializer.output());
    }

    /// Sql `Serializer` implements `Serializer` to generate Surreal SQL queries.
    pub struct Sql {
        has_clause: bool,
        output: String,
        clauses: Vec<SqlClause>,
    }

    /// SqlClause is used to store the conjunction and condition state of a clause.
    pub struct SqlClause {
        conjunction: String,
        has_condition: bool,
    }

    impl Sql {
        /// Create a new `Serializer` with the minimum output required to query a
        /// SurrealDB database.
        pub fn new() -> Self {
            Self {
                has_clause: false,
                output: String::from("SELECT * FROM type::table($table)"),
                clauses: vec![],
            }
        }

        /// Returns the generated SQL query.
        pub fn output(&self) -> &str {
            &self.output
        }

        // Logic common to both clause methods.
        fn add_clause(&mut self) {
            // add the WHERE keyword when this is the first clause
            if !self.has_clause {
                self.output.push_str(" WHERE ");
            }
            self.has_clause = true;

            // only add a conjunction when the current clause already has a condition
            if let Some(current) = self.clauses.last_mut() {
                if current.has_condition {
                    self.output.push_str(&current.conjunction);
                }
                current.has_condition = true;
            }
            self.output.push_str("(");
        }
    }

    impl SqlClause {
        /// Create a new `SqlClause` with the given conjunction.
        pub fn new(conjunction: impl Into<String>) -> Self {
            Self {
                conjunction: conjunction.into(),
                has_condition: false,
            }
        }
    }

    /// Serialize `MessagesQuery` to Surreal SQL.
    impl Serializer for Sql {
        type Clause = Self;

        fn or_clause(&mut self) -> &mut Self::Clause {
            self.add_clause();
            self.clauses.push(SqlClause::new(" OR "));
            self
        }

        fn and_clause(&mut self) -> &mut Self::Clause {
            self.add_clause();
            self.clauses.push(SqlClause::new(" AND "));
            self
        }

        fn order(&mut self, field: &str, sort: Dir) {
            match sort {
                Dir::Asc => self.output.push_str(&format!(" ORDER BY {field} COLLATE ASC")),
                Dir::Desc => self.output.push_str(&format!(" ORDER BY {field} COLLATE DESC")),
            }
        }

        fn limit(&mut self, limit: usize, offset: usize) {
            self.output.push_str(&format!(" LIMIT {limit}"));
            self.output.push_str(&format!(" START {offset}"));
        }
    }

    impl Clause for Sql {
        fn condition(&mut self, field: &str, op: Op, value: Value) {
            // only add a conjunction when the current clause already has a condition
            let current = self.clauses.last_mut().unwrap();
            if current.has_condition {
                self.output.push_str(&current.conjunction);
            }
            current.has_condition = true;

            let op = match op {
                Op::Eq => " = ",
                Op::Gt => " > ",
                Op::Ge => " >= ",
                Op::Lt => " < ",
                Op::Le => " <= ",
                Op::Like => " LIKE ",
            };

            match value {
                Value::Str(s) => self.output.push_str(&format!("{field}{op}'{s}'")),
                Value::Int(i) => self.output.push_str(&format!("{field}{op}{i}")),
                Value::Bool(b) => {
                    if b {
                        self.output.push_str(&format!("{field} = true"))
                    } else {
                        self.output.push_str(&format!("(!{field} OR {field} = false)"))
                    }
                }
            }
        }

        fn close(&mut self) {
            self.clauses.pop();
            self.output.push_str(")");
        }
    }
}
