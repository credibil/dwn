//! # Protocols

pub mod configure;
pub mod query;

pub use self::configure::{
    Action, ActionRule, Actor, Configure, ConfigureBuilder, ConfigureReply, Definition,
    ProtocolType, RuleSet,
};
pub use self::query::{Query, QueryBuilder, QueryReply};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

/// The protocol path of the `request` record.
pub const REQUEST_PATH: &str = "request";

/// The protocol path of the `grant` record.
pub const GRANT_PATH: &str = "grant";

///The protocol path of the `revocation` record.
pub const REVOCATION_PATH: &str = "grant/revocation";


