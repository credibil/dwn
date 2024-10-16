//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use super::Filter;
use crate::provider::Provider;
use crate::service::Authorization;
use crate::{Cursor, Descriptor};

/// Messages Query payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Messages Query reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when querying messages.
    pub filters: Vec<Filter>,

    /// The pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Handle a query message.
pub async fn handle(
    tenant: &str, message: Query, provider: impl Provider,
) -> anyhow::Result<QueryReply> {
    todo!()
}
