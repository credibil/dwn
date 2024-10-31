//! # Protocols

pub mod configure;
pub mod query;

use anyhow::Result;

pub use crate::protocols::configure::{
    Configure, ConfigureBuilder, ConfigureReply, ProtocolDefinition, ProtocolType, RuleSet,
};
pub use crate::protocols::query::{Query, QueryBuilder, QueryReply};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

/// Permissions protocol definition.
pub fn definition() -> Result<ProtocolDefinition> {
    let bytes = include_bytes!("protocols/default_protocol.json");
    serde_json::from_slice(bytes).map_err(|e| e.into())
}
