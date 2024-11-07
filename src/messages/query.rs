//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use super::Filter;
use crate::auth::Authorization;
use crate::provider::Provider;
use crate::{Cursor, Result};

/// Handle a query message.
///
/// # Errors
/// TODO: Add errors
pub(crate) fn handle(
    _tenant: &str, _message: Query, _provider: impl Provider,
) -> Result<QueryReply> {
    todo!()
}

/// Messages Query payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: Descriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Messages Query reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct QueryReply {
    /// The Query descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: crate::Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<Filter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}
