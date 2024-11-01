//! # Database Query Utilities

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A filter for querying data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Filter {
    /// A list of criteria for the filter.
    #[serde(flatten)]
    pub criteria: BTreeMap<String, Criterion>,
}

/// A criterion for filtering data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Criterion {
    /// Filter by a specific value.
    Single(Compare),

    /// Filter by one of the values in the set.
    OneOf(Vec<Value>),

    /// Filter values within a range.
    Range(Range),
}

/// Define a range to use in filtering values.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Range {
    /// Filter values starting from.
    pub from: Compare,

    /// Filter values up to.
    pub to: Compare,
}

/// Comparators for filtering value ranges.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Compare {
    /// Equal to the value.
    Equal(Value),

    /// Not equal to the value.
    NotEqual(Value),

    /// Greater than the value.
    GreaterThan(Value),

    /// Greater than or equal to the value.
    GreaterThanOrEqual(Value),

    /// Less than the value.
    LessThan(Value),

    /// Less than or equal to the value.
    LessThanOrEqual(Value),
}
