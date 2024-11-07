//! # Protocols

pub mod configure;
pub mod query;

pub use crate::protocols::configure::{
    Action, ActionRule, Actor, Configure, ConfigureBuilder, ConfigureReply,
    Definition, ProtocolType, RuleSet,
};
pub use crate::protocols::query::{Query, QueryBuilder, QueryReply};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

/// The protocol path of the `request` record.
pub const REQUEST_PATH: &str = "request";

/// The protocol path of the `grant` record.
pub const GRANT_PATH: &str = "grant";

///The protocol path of the `revocation` record.
pub const REVOCATION_PATH: &str = "grant/revocation";

impl Default for Definition {
    fn default() -> Self {
        let bytes = include_bytes!("protocols/default_protocol.json");
        serde_json::from_slice(bytes).expect("should deserialize")
    }
}
