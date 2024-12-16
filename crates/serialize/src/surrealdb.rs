// use std::collections::VecDeque;
use crate::{Clause, Dir, Op, Value};

pub struct Serializer {
    pub output: String,
    pub clauses: Vec<SqlClause>,
}

pub struct SqlClause {
    pub conjunction: String,
    pub initial: bool,
}

/// Serialize `MessagesQuery` to Surreal SQL.
impl crate::Serializer for Serializer {
    type Clause = Self;

    fn or_clause(&mut self) -> &mut Self::Clause {
        if let Some(current) = self.clauses.last_mut() {
            if !current.initial {
                self.output.push_str(&current.conjunction);
            }
            current.initial = false;
        }
        self.output.push_str("(");

        self.clauses.push(SqlClause {
            conjunction: String::from(" OR "),
            initial: true,
        });
        self
    }

    fn and_clause(&mut self) -> &mut Self::Clause {
        if let Some(current) = self.clauses.last_mut() {
            if !current.initial {
                self.output.push_str(&current.conjunction);
            }
            current.initial = false;
        }
        self.output.push_str("(");

        self.clauses.push(SqlClause {
            conjunction: String::from(" AND "),
            initial: true,
        });
        self
    }

    fn order(&mut self, field: &str, sort: Dir) {
        match sort {
            Dir::Asc => self.output.push_str(&format!(" ORDER BY {field} COLLATE ASC")),
            Dir::Desc => self.output.push_str(&format!(" ORDER BY {field} COLLATE DESC")),
        }
    }
}

/// Serialize `MessagesFilter` to Surreal SQL.
impl Clause for Serializer {
    fn add(&mut self, field: &str, op: Op, value: Value) {
        let clause = self.clauses.last_mut().unwrap();
        if !clause.initial {
            self.output.push_str(&clause.conjunction);
        }
        clause.initial = false;

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
