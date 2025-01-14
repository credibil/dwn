//! # Protocols

mod configure;
pub(crate) mod integrity;
mod query;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

pub use self::configure::{
    Action, ActionRule, Actor, Configure, ConfigureDescriptor, ConfigureReply, Definition,
    ProtocolType, RuleSet, validate_structure,
};
pub use self::query::{Query, QueryBuilder, QueryReply};
use crate::Range;

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

/// The protocol path of the `request` record.
pub const REQUEST_PATH: &str = "request";

/// The protocol path of the `grant` record.
pub const GRANT_PATH: &str = "grant";

///The protocol path of the `revocation` record.
pub const REVOCATION_PATH: &str = "grant/revocation";

/// Protocol filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolsFilter {
    /// Protocol matching the specified protocol.
    pub protocol: String,
}

/// Default protocol definition.
pub static DEFINITION: LazyLock<Definition> = LazyLock::new(|| {
    // default types
    let mut types = BTreeMap::new();
    let default_type = ProtocolType {
        data_formats: Some(vec!["application/json".to_string()]),
        ..ProtocolType::default()
    };
    types.insert("request".to_string(), default_type.clone());
    types.insert("grant".to_string(), default_type.clone());
    types.insert("revocation".to_string(), default_type);

    // default structure (aka rules)
    let default_size = Range {
        min: None,
        max: Some(10000),
    };

    let mut structure = BTreeMap::new();
    structure.insert("request".to_string(), RuleSet {
        size: Some(default_size.clone()),
        actions: Some(vec![ActionRule {
            who: Some(Actor::Anyone),
            can: vec![Action::Create],
            ..ActionRule::default()
        }]),
        ..RuleSet::default()
    });
    structure.insert("grant".to_string(), RuleSet {
        size: Some(default_size.clone()),
        actions: Some(vec![ActionRule {
            who: Some(Actor::Recipient),
            of: Some("grant".to_string()),
            can: vec![Action::Read, Action::Query],
            ..ActionRule::default()
        }]),
        // revocation is nested under grant
        structure: BTreeMap::from([("revocation".to_string(), RuleSet {
            size: Some(default_size),
            actions: Some(vec![ActionRule {
                who: Some(Actor::Anyone),
                can: vec![Action::Read],
                ..ActionRule::default()
            }]),
            ..RuleSet::default()
        })]),
        ..RuleSet::default()
    });

    Definition {
        protocol: PROTOCOL_URI.to_string(),
        published: true,
        types,
        structure,
    }
});
