//! # Serialize

pub mod surreal;

/// `QuerySerializer` is used to provide overridable query serialization.
///
/// The default implementation serializes the query to a SQL string, but can be
/// overridden by implementers to provide custom serialization. For example, a
/// BSON query for `MongoDB`.
///
/// # Example
///
/// ```rust
/// use vercre_dwn::store::{Query,QuerySerializer};
///
/// struct CustomSerializer(Query);
///
/// QuerySerializer for CustomSerializer {
///    type Output = String;
///
///    fn serialize(&self) -> Self::Output {
///        format!("SELECT * FROM message WHERE protocol={}", self.0.protocol)
///    }
/// }
/// ```
pub trait QuerySerializer {
    /// The output type of the serialization.
    type Output;

    /// Serialize the query to the output type.
    fn serialize(&self) -> Self::Output;
}
