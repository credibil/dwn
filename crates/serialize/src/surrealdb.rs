//! # Surreal DB

use dwn_node::store::serializer::{Clause, Op, Serializer, SortField, Value};

/// Surreal DB `Serializer` implements `Serializer` to generate Surreal SQL queries.
pub struct Sql {
    has_clause: bool,
    output: String,
    clauses: Vec<SqlClause>,
}

/// `SqlClause` is used to store the conjunction and condition state of a clause.
pub struct SqlClause {
    conjunction: String,
    has_condition: bool,
}

impl Default for Sql {
    fn default() -> Self {
        Self::new()
    }
}

impl Sql {
    /// Create a new `Serializer` with the minimum output required to query a
    /// `SurrealDB` database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            has_clause: false,
            output: String::from("SELECT * FROM type::table($table)"),
            clauses: vec![],
        }
    }

    /// Returns the generated SQL query.
    #[must_use]
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
        self.output.push('(');
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

    fn order(&mut self, sort_fields: &[SortField]) {
        self.output.push_str(" ORDER BY ");
        for field in sort_fields {
            match field {
                SortField::Asc(f) => self.output.push_str(&format!("{f} ASC,")),
                SortField::Desc(f) => self.output.push_str(&format!("{f} DESC,")),
            }
        }

        // remove trailing comma
        self.output.pop();
    }

    // LATER: use database for pagination when spec allows
    // fn limit(&mut self, limit: usize, offset: usize) {
    //     self.output.push_str(&format!(" LIMIT {limit}"));
    //     self.output.push_str(&format!(" START {offset}"));
    // }
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
                    self.output.push_str(&format!("{field} = true"));
                } else {
                    self.output.push_str(&format!("(!{field} OR {field} = false)"));
                }
            }
        }
    }

    fn close(&mut self) {
        self.clauses.pop();
        self.output.push(')');
    }
}
