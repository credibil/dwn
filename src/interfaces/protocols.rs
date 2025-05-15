//! # Protocols Configure
//!
//! The protocols configure endpoint handles `ProtocolsConfigure` messages —
//! requests to write to [`Configure`] records to the DWN's
//! [`crate::provider::MessageStore`].

use std::collections::BTreeMap;
#[cfg(feature = "server")]
use std::collections::HashMap;

use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authorization::Authorization;
use crate::bad;
use crate::handlers::Result;
use crate::hd_key::{self, DerivationPath, DerivationScheme, DerivedPrivateJwk, PrivateKeyJwk};
use crate::interfaces::Descriptor;
use crate::store::Cursor;
use crate::utils::cid;

/// Default protocol for managing web node permission grants.
pub const PROTOCOL_URI: &str = "https://credibil.website/dwn/permissions";

/// The protocol path of the `request` record.
pub const REQUEST_PATH: &str = "request";

/// The protocol path of the `grant` record.
pub const GRANT_PATH: &str = "grant";

///The protocol path of the `revocation` record.
pub const REVOCATION_PATH: &str = "grant/revocation";

/// The [`Configure`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Configure {
    /// The Configure descriptor.
    pub descriptor: ConfigureDescriptor,

    /// The message authorization.
    pub authorization: Authorization,

    /// Flattened fields as key/value pairs to use for indexing stored records.
    #[serde(skip)]
    #[cfg(feature = "server")]
    pub(crate) indexes: HashMap<String, String>,
}

impl Configure {
    /// Compute the content identifier (CID) for the `Configure` message.
    ///
    /// # Errors
    ///
    /// This method will fail if the message cannot be serialized to CBOR.
    pub fn cid(&self) -> anyhow::Result<String> {
        cid::from_value(self)
    }
}

/// The [`Configure`] message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigureDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The protocol definition.
    pub definition: Definition,
}

/// Protocol definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Definition {
    /// Protocol URI.
    pub protocol: String,

    /// Specifies whether the `Definition` can be returned by unauthorized
    /// `ProtocolsQuery`.
    pub published: bool,

    /// Protocol types.
    pub types: BTreeMap<String, ProtocolType>,

    /// Protocol rules.
    pub structure: BTreeMap<String, RuleSet>,
}

impl Definition {
    /// Returns a new [`Definition`]
    #[must_use]
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            ..Self::default()
        }
    }

    /// Whether the definition should be published.
    #[must_use]
    pub const fn published(mut self, published: bool) -> Self {
        self.published = published;
        self
    }

    /// Add a protocol type.
    #[must_use]
    pub fn add_type(mut self, name: impl Into<String>, type_: ProtocolType) -> Self {
        self.types.insert(name.into(), type_);
        self
    }

    /// Add a rule.
    #[must_use]
    pub fn add_rule(mut self, name: impl Into<String>, rule_set: RuleSet) -> Self {
        self.structure.insert(name.into(), rule_set);
        self
    }

    /// Derives public encryption key and adds it to the `$encryption` property
    /// for each protocol path segment.
    ///
    /// # Errors
    ///
    /// This method will fail when an error occurs deriving the public key.
    pub fn with_encryption(
        mut self, root_key_id: &str, private_key_jwk: PrivateKeyJwk,
    ) -> Result<Self> {
        let root_key = DerivedPrivateJwk {
            root_key_id: root_key_id.to_string(),
            derivation_scheme: DerivationScheme::ProtocolPath,
            derivation_path: None,
            derived_private_key: private_key_jwk,
        };

        // create protocol-derived jwk
        let path = vec![DerivationScheme::ProtocolPath.to_string(), self.protocol.clone()];
        let derived_jwk = hd_key::derive_jwk(root_key, &DerivationPath::Relative(&path))?;

        // recursively add `encryption` property to each rule set
        add_encryption(&mut self.structure, &derived_jwk)?;

        Ok(self)
    }
}

fn add_encryption(
    structure: &mut BTreeMap<String, RuleSet>, parent_key: &DerivedPrivateJwk,
) -> Result<()> {
    for (key, rule_set) in structure {
        let derived_jwk =
            hd_key::derive_jwk(parent_key.clone(), &DerivationPath::Relative(&[key.clone()]))?;
        let public_key_jwk = derived_jwk.derived_private_key.public_key.clone();
        rule_set.encryption = Some(PathEncryption {
            root_key_id: parent_key.root_key_id.clone(),
            public_key_jwk,
        });

        // recurse into nested rules sets
        add_encryption(&mut rule_set.structure, &derived_jwk)?;
    }
    Ok(())
}

/// Protocol type
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolType {
    /// The protocol schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Data formats supported by the protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_formats: Option<Vec<String>>,
}

/// Protocol rule set.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    /// Encryption setting for objects that are in this protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$encryption")]
    pub encryption: Option<PathEncryption>,

    /// The protocol action rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$actions")]
    pub actions: Option<Vec<ActionRule>>,

    /// Storable is a role record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$role")]
    pub role: Option<bool>,

    /// If $size is set, the record size in bytes must be within the limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$size")]
    pub size: Option<Size>,

    /// Tags for this protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$tags")]
    pub tags: Option<Tags>,

    /// JSON Schema verifies that properties other than properties prefixed
    /// with $ will actually have type `ProtocolRuleSet`
    #[serde(flatten)]
    pub structure: BTreeMap<String, RuleSet>,
}

/// Config for protocol-path encryption scheme.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathEncryption {
    /// The ID of the root key that derives the public key at this protocol path for encrypting the symmetric key used for data encryption.
    pub root_key_id: String,

    /// Public key for encrypting the symmetric key used for data encryption.
    pub public_key_jwk: PublicKeyJwk,
}

/// Rules are used to define which actors can access records for a given
/// protocol path. Rules take three forms, e.g.:
///
/// 1. Anyone can create:
/// ```json
///   {
///     who: 'anyone',
///     can: ['create']
///   }
/// ```
///
/// 2. Author of `protocol_path` can create; OR Recipient of `protocol_path`
///    can write:
/// ```json
///   {
///     who: 'recipient'
///     of: 'requestForQuote',
///     can: ['create']
///   }
/// ```
///
/// 3. Role can create:
/// ```json
///   {
///     role: 'friend',
///     can: ['create']
///   }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRule {
    /// If `who` === 'anyone', then `of` must be omitted. Otherwise `of` must be present.
    /// Mutually exclusive with `role`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who: Option<Actor>,

    /// The protocol path of a role record type marked with $role: true.
    /// Mutually exclusive with `who`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Protocol path.
    /// Must be present if `who` === 'author' or 'recipient'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<String>,

    /// Array of actions that the actor/role can perform.
    /// N.B. 'query' and 'subscribe' are only supported for `role` rules.
    pub can: Vec<Action>,
}

/// Actor types.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Actor {
    /// Anyone can perform the action.
    #[default]
    Anyone,

    /// Author of the ??.
    Author,

    /// Recipient of the ??.
    Recipient,
}

/// Rule actions.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    /// Create
    Create,

    /// Delete
    Delete,

    /// Prune
    Prune,

    /// Query
    Query,

    /// Subscribe
    Subscribe,

    /// Read
    #[default]
    Read,

    /// Update
    Update,

    /// Co-delete
    #[serde(rename = "co-delete")]
    CoDelete,

    /// Co-prune
    #[serde(rename = "co-prune")]
    CoPrune,

    /// Co-update
    #[serde(rename = "co-update")]
    CoUpdate,
}

/// Data size range.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Size {
    /// The range's minimum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<usize>,

    /// The range's maximum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
}

/// Protocol tags
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tags {
    /// Tags required for this protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$requiredTags")]
    pub required: Option<Vec<String>>,

    /// Allow tags other than those explicitly listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$allowUndefinedTags")]
    pub allow_undefined: Option<bool>,

    /// Tag properties
    #[serde(flatten)]
    pub undefined: BTreeMap<String, Value>,
}

/// [`ConfigureReply`] is returned by the handler in the
/// [`crate::endpoint::Reply`] `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigureReply {
    /// The [`Configure`] entry.
    #[serde(flatten)]
    pub message: Configure,
}

/// Access level for query.
#[derive(PartialEq, Eq, PartialOrd)]
pub enum Access {
    /// Query published records only
    Published,

    /// Query published and unpublished records
    Unpublished,
}

/// The [`Query`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

/// The [`Query`] message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<ProtocolsFilter>,
}

/// [`QueryReply`] is returned by the handler in the [`crate::endpoint::Reply`]
/// `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryReply {
    /// [`Configure`] entries matching the query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<Configure>>,

    /// Pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// The Protocols filter is used when querying for protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolsFilter {
    /// Protocol matching the specified protocol.
    pub protocol: String,
}

/// Verify the structure (rule sets) of the protocol definition.
pub(crate) fn validate_structure(definition: &Definition) -> Result<()> {
    let keys = definition.types.keys().collect::<Vec<&String>>();

    // parse rule set for roles
    let roles = role_paths("", &definition.structure, &[])?;

    // validate rule set hierarchy
    for rule_set in definition.structure.values() {
        validate_rule_set(rule_set, "", &keys, &roles)?;
    }

    Ok(())
}

// Validates a rule set structure, recursively validating nested rule sets.
fn validate_rule_set(
    rule_set: &RuleSet, protocol_path: &str, types: &Vec<&String>, roles: &Vec<String>,
) -> Result<()> {
    // validate size rule
    if let Some(size) = &rule_set.size {
        if size.max.is_some() && size.min > size.max {
            return Err(bad!("invalid size range"));
        }
    }

    // validate tags schemas
    if let Some(tags) = &rule_set.tags {
        for tag in tags.undefined.keys() {
            let schema = serde_json::from_str(tag)?;
            jsonschema::validator_for(&schema)
                .map_err(|e| bad!("tag schema validation error: {e}"))?;
        }
    }

    // validate action rules
    let empty = Vec::new();
    let mut action_iter = rule_set.actions.as_ref().unwrap_or(&empty).iter();

    while let Some(action) = action_iter.next() {
        // validate action's `role` property, if exists.
        if let Some(role) = &action.role {
            // role must contain valid protocol paths to a role record
            if !roles.contains(role) {
                return Err(bad!("missing role {role} in action"));
            }

            // if ANY `can` actions are read-like ('read', 'query', 'subscribe')
            // then ALL read-like actions must be present
            let mut read_actions = vec![Action::Read, Action::Query, Action::Subscribe];
            read_actions.retain(|ra| action.can.contains(ra));

            // intersection of `read_actions` and `can`: it should be empty or 3
            if !read_actions.is_empty() && read_actions.len() != 3 {
                return Err(bad!("role {role} is missing read-like actions"));
            }
        }

        // when `who` is `anyone`, `of` cannot be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Anyone) && action.of.is_some() {
            return Err(bad!("`of` must not be set when `who` is \"anyone\""));
        }

        // When `who` is "recipient" and `of` is unset, `can` must only contain
        // `co-update`, `co-delete`, and `co-prune`.
        //
        // Any other action is disallowed because:
        //   - `read` - recipients are always allowed to read
        //   - `write` - unset `of` implies the recipient of this record, but there
        //      is no 'recipient' until the record has been created.
        //   - `query` - query is authorized using roles, not recipients.
        if action.who.as_ref().is_some_and(|w| w == &Actor::Recipient) && action.of.is_none() {
            let allowed = [Action::CoUpdate, Action::CoDelete, Action::CoPrune];
            if !allowed.iter().any(|ra| action.can.contains(ra)) {
                return Err(bad!(
                    "recipient action must contain only co-update, co-delete, and co-prune",
                ));
            }
        }

        // when `who` is set to "author" then `of` must be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Author) && action.of.is_none() {
            return Err(bad!("`of` must be set when `who` is set to 'author'"));
        }

        // when `can` contains `update` or `delete`, it must also contain `create`
        if action.can.contains(&Action::Update) && !action.can.contains(&Action::Create) {
            return Err(bad!("action rule {action:?} contains 'update' but no 'create'"));
        }
        if action.can.contains(&Action::Delete) && !action.can.contains(&Action::Create) {
            return Err(bad!("action rule {action:?} contains 'delete' but no 'create'"));
        }

        // ensure no duplicate actors or roles in the remaining action rules
        // ie. no two action rules can have the same combination of `who` + `of` or `role`.
        for other in action_iter.clone() {
            if action.who.is_some() {
                if action.who == other.who && action.of == other.of {
                    return Err(bad!("an actor may only have one rule within a rule set"));
                }
            } else if action.role == other.role {
                return Err(bad!(
                    "more than one action rule per role {:?} not allowed within a rule set: {action:?}",
                    action.role
                ));
            }
        }
    }

    // verify nested rule sets
    for (set_name, rule_set) in &rule_set.structure {
        if !types.contains(&set_name) {
            return Err(bad!("rule set {set_name} is not declared as an allowed type"));
        }
        let protocol_path = if protocol_path.is_empty() {
            set_name
        } else {
            &format!("{protocol_path}/{set_name}")
        };
        validate_rule_set(rule_set, protocol_path, types, roles)?;
    }

    Ok(())
}

// Parses the given rule set hierarchy to get all the role protocol paths.
fn role_paths(
    protocol_path: &str, structure: &BTreeMap<String, RuleSet>, roles: &[String],
) -> Result<Vec<String>> {
    // restrict to max depth of 10 levels
    if protocol_path.split('/').count() > 10 {
        return Err(bad!("Storable nesting depth exceeded 10 levels."));
    }

    let mut roles = roles.to_owned();

    // only check for roles in nested rule sets
    for (rule_name, rule_set) in structure {
        let protocol_path = if protocol_path.is_empty() {
            rule_name
        } else {
            &format!("{protocol_path}/{rule_name}")
        };

        if rule_set.role.is_some() {
            roles.push(protocol_path.to_string());
        } else {
            roles = role_paths(protocol_path, &rule_set.structure, &roles)?;
        }
    }

    Ok(roles)
}
