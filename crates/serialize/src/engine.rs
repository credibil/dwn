use anyhow::Result;
use vercre_dwn::store::{
    Lower, MessagesFilter, MessagesQuery, ProtocolsQuery, Query, RecordsFilter, RecordsQuery, Sort,
    TagFilter, Upper,
};
use vercre_dwn::{Interface, Method, Quota};

use crate::{Clause, Dir, Op, Serialize, Serializer, Value};

/// Serialize a supported DWN query to Surreal SQL.
impl Serialize for Query {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()> {
        match self {
            Query::Messages(query) => query.serialize(serializer),
            Query::Protocols(query) => query.serialize(serializer),
            Query::Records(query) => query.serialize(serializer),
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
            filters_or.close()
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
        // if let Some(pagination) = &self.pagination {
        //     if let Some(limit) = pagination.limit {
        //         sql.push_str(&format!(" LIMIT {limit}"));
        //     }

        //     if let Some(offset) = pagination.offset {
        //         sql.push_str(&format!(" START {offset}"));
        //     }
        // }

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
            let field = "descriptor.dateCreated";
            let range_and = outer_and.and_clause();
            match date_range.lower {
                Some(lower) => {
                    range_and.condition(field, Op::Gt, Value::Str(&lower.to_string()));
                }
                None => {}
            }
            match date_range.upper {
                Some(upper) => {
                    range_and.condition(field, Op::Lt, Value::Str(&upper.to_string()));
                }
                None => {}
            }
            range_and.close();
        }
        if let Some(date_range) = &self.date_published {
            let field = "descriptor.datePublished";
            let range_and = outer_and.and_clause();
            match date_range.lower {
                Some(lower) => {
                    range_and.condition(field, Op::Gt, Value::Str(&lower.to_string()));
                }
                None => {}
            }
            match date_range.upper {
                Some(upper) => {
                    range_and.condition(field, Op::Lt, Value::Str(&upper.to_string()));
                }
                None => {}
            }
            range_and.close();
        }
        if let Some(date_range) = &self.date_updated {
            let field = "descriptor.dateUpdated";
            let range_and = outer_and.and_clause();
            match date_range.lower {
                Some(lower) => {
                    range_and.condition(field, Op::Gt, Value::Str(&lower.to_string()));
                }
                None => {}
            }
            match date_range.upper {
                Some(upper) => {
                    range_and.condition(field, Op::Lt, Value::Str(&upper.to_string()));
                }
                None => {}
            }
            range_and.close();
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
            let tags_and = outer_and.and_clause();
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
            tags_and.close()
        }

        outer_and.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surrealdb::Serializer;

    #[test]
    fn test_serialize() {
        let query = Query::Protocols(ProtocolsQuery {
            protocol: Some("dwn".to_string()),
            published: Some(false),
            // published: None,
        });

        let mut serializer = Serializer::new();

        query.serialize(&mut serializer).unwrap();
        println!("{}", serializer.output());
    }
}
