#![allow(missing_docs)]

//! # Serialize

pub mod engine;
pub mod surrealdb;

use anyhow::Result;

/// `Serialize` is used to provide overridable query serialization.
///
/// The default implementation serializes the query to a SQL string, but can be
/// overridden by implementers to provide custom serialization. For example, a
/// BSON query for `MongoDB`.
///
/// # Example
///
/// ```rust
/// use vercre_dwn::store::{Query, QuerySerializer};
///
/// struct CustomSerializer(Query);
///
/// impl QuerySerializer for CustomSerializer {
///     type Output = String;
///
///     fn serialize(&self) -> Self::Output {
///         format!("SELECT * FROM message WHERE protocol={}", self.0.protocol)
///     }
/// }
/// ```
pub trait Serialize {
    fn serialize<S: Serializer>(&self, serializer: &mut S) -> Result<()>;
}

pub trait Serializer {
    type Clause: Clause;

    fn or_clause(&mut self) -> &mut Self::Clause;
    fn and_clause(&mut self) -> &mut Self::Clause;
    fn order(&mut self, field: &str, sort: Dir);
}

pub trait Clause: Serializer {
    fn add(&mut self, field: &str, op: Op, value: Value);
    fn close(&mut self);
}

pub enum Value<'a> {
    Bool(bool),
    Int(usize),
    Str(&'a str),
}

pub enum Op {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    Like,
}

pub enum Dir {
    Asc,
    Desc,
}
