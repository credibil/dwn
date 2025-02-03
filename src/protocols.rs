//! # Protocols Handlers
//!
//! Protocols handlers handle incoming `Protocols` interface messages.

mod configure;
pub mod query;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

pub use self::configure::{
    Action, ActionRule, Actor, Configure, ConfigureDescriptor, Definition, ProtocolType, RuleSet,
    Size, validate_structure,
};
pub use self::query::{Query, QueryDescriptor};
use crate::provider::MessageStore;
use crate::{Result, store};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://vercre.website/dwn/permissions";

/// The protocol path of the `request` record.
pub const REQUEST_PATH: &str = "request";

/// The protocol path of the `grant` record.
pub const GRANT_PATH: &str = "grant";

///The protocol path of the `revocation` record.
pub const REVOCATION_PATH: &str = "grant/revocation";

/// The Protocols filter is used when querying for protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolsFilter {
    /// Protocol matching the specified protocol.
    pub protocol: String,
}

/// Define a default protocol definition.
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

    let default_size = Size {
        min: None,
        max: Some(10000),
    };

    // default structure (aka rules)
    let structure = BTreeMap::from([
        (
            "request".to_string(),
            RuleSet {
                size: Some(default_size.clone()),
                actions: Some(vec![ActionRule {
                    who: Some(Actor::Anyone),
                    can: vec![Action::Create],
                    ..ActionRule::default()
                }]),
                ..RuleSet::default()
            },
        ),
        (
            "grant".to_string(),
            RuleSet {
                size: Some(default_size.clone()),
                actions: Some(vec![ActionRule {
                    who: Some(Actor::Recipient),
                    of: Some("grant".to_string()),
                    can: vec![Action::Read, Action::Query],
                    ..ActionRule::default()
                }]),
                // revocation is nested under grant
                structure: BTreeMap::from([(
                    "revocation".to_string(),
                    RuleSet {
                        size: Some(default_size),
                        actions: Some(vec![ActionRule {
                            who: Some(Actor::Anyone),
                            can: vec![Action::Read],
                            ..ActionRule::default()
                        }]),
                        ..RuleSet::default()
                    },
                )]),
                ..RuleSet::default()
            },
        ),
    ]);

    Definition {
        protocol: PROTOCOL_URI.to_string(),
        published: true,
        types,
        structure,
    }
});

// Fetch published protocols matching the filter
pub async fn fetch_config(
    owner: &str, protocol: Option<String>, store: &impl MessageStore,
) -> Result<Option<Vec<Configure>>> {
    // build query
    let mut builder = store::ProtocolsQueryBuilder::new();
    if let Some(protocol) = protocol {
        builder = builder.protocol(&protocol);
    }

    // execute query
    let (messages, _) = store.query(owner, &builder.build()).await?;
    if messages.is_empty() {
        return Ok(None);
    }

    // unpack messages
    let mut entries = vec![];
    for message in messages {
        entries.push(Configure::try_from(message)?);
    }

    Ok(Some(entries))
}
