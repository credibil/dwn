//! # Protocols

pub mod configure;
pub mod query;

pub use crate::protocols::configure::{
    Configure, ConfigureBuilder, ConfigureReply, Definition, ProtocolType, RuleSet,
};
pub use crate::protocols::query::{Query, QueryBuilder, QueryReply};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

impl Default for Definition {
    fn default() -> Self {
        let bytes = include_bytes!("protocols/default_protocol.json");
        serde_json::from_slice(bytes).expect("should deserialize")
    }
}
