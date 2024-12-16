//! # Serialize

mod engine;
pub mod surrealdb;

use anyhow::Result;

/// `Serialize` is used to provide overridable query serialization.
pub trait Serialize {
    /// Serialize a DWN query using the given `Serializer`.
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()>;
}

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

    /// Create a new query clause that uses an OR conjunction to join clause
    /// conditions.
    fn or_clause(&mut self) -> &mut Self::Clause;

    /// Create a new query clause that uses an AND conjunction to join clause
    /// conditions.
    fn and_clause(&mut self) -> &mut Self::Clause;

    /// Specifies an ordering clause to use for query results.
    fn order(&mut self, field: &str, sort: Dir);
}

/// A `Clause` is used to generate a query clause contain one or more conditions.
pub trait Clause: Serializer {
    /// Adds a condition to the clause.
    fn condition(&mut self, field: &str, op: Op, value: Value);

    /// Close the clause.
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
