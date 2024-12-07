//! # Protocols Configure
//!
//! Decentralized Web Node messaging framework.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::jwk::PublicKeyJwk;

use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::protocols::query;
use crate::provider::{EventLog, EventStream, MessageStore, Provider, Signer};
use crate::records::DelegatedGrant;
use crate::store::{Entry, EntryType};
use crate::{
    Descriptor, Error, Interface, Method, Range, Result, forbidden, permissions, schema,
    unexpected, utils,
};

/// Process query message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, configure: Configure, provider: &impl Provider,
) -> Result<Reply<ConfigureReply>> {
    configure.authorize(owner, provider).await?;

    // validate the message
    configure.validate()?;

    // find any matching protocol entries
    let results = query::fetch_config(
        owner,
        Some(configure.descriptor.definition.protocol.clone()),
        provider,
    )
    .await?;

    // determine incoming message is the latest
    if let Some(existing) = &results {
        let Some(latest) = existing.iter().max_by(|a, b| {
            a.descriptor.base.message_timestamp.cmp(&b.descriptor.base.message_timestamp)
        }) else {
            return Err(unexpected!("no matching protocol entries found"));
        };

        let configure_ts = configure.descriptor.base.message_timestamp.timestamp_micros();
        let latest_ts = latest.descriptor.base.message_timestamp.timestamp_micros();

        // when latest message is more recent than incoming message
        if latest_ts > configure_ts {
            return Err(Error::Conflict("message is not the latest".to_string()));
        }
        // when latest message CID is larger than incoming message CID
        if latest_ts == configure_ts && latest.cid()?.cmp(&configure.cid()?) == Ordering::Greater {
            return Err(Error::Conflict("message CID is smaller than existing entry".to_string()));
        }

        // remove existing entries
        for e in existing {
            let cid = cid::from_value(&e)?;
            MessageStore::delete(provider, owner, &cid).await?;
            EventLog::delete(provider, owner, &cid).await?;
        }
    }

    // save the incoming message
    let entry = Entry::from(&configure);
    MessageStore::put(provider, owner, &entry).await?;
    EventLog::append(provider, owner, &entry).await?;
    EventStream::emit(provider, owner, &entry).await?;

    Ok(Reply {
        status: Status {
            code: StatusCode::ACCEPTED.as_u16(),
            detail: None,
        },
        body: Some(ConfigureReply { message: configure }),
    })
}

/// Protocols Configure payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Configure {
    /// The Configure descriptor.
    pub descriptor: ConfigureDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

#[async_trait]
impl Message for Configure {
    type Reply = ConfigureReply;

    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

/// Configure reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigureReply {
    #[serde(flatten)]
    message: Configure,
}

impl From<Configure> for Entry {
    fn from(configure: Configure) -> Self {
        Self {
            message: EntryType::Configure(configure),
            indexes: Map::new(),
        }
    }
}

impl From<&Configure> for Entry {
    fn from(configure: &Configure) -> Self {
        Self {
            message: EntryType::Configure(configure.clone()),
            indexes: Map::new(),
        }
    }
}

impl TryFrom<Entry> for Configure {
    type Error = crate::Error;

    fn try_from(record: Entry) -> Result<Self> {
        match record.message {
            EntryType::Configure(configure) => Ok(configure),
            _ => Err(unexpected!("expected `ProtocolsConfigure` message")),
        }
    }
}

impl Configure {
    /// Check message has sufficient privileges.
    ///
    /// # Errors
    /// LATER: Add errors
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;

        if authzn.author()? == owner {
            return Ok(());
        }

        // permission grant
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Err(forbidden!("author has no grant"));
        };
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.author()?, self.descriptor(), store).await?;

        // when the grant scope does not specify a protocol, it is an unrestricted grant
        let Some(protocol) = grant.data.scope.protocol() else {
            return Ok(());
        };
        if protocol != self.descriptor.definition.protocol {
            return Err(forbidden!("message and grant protocols do not match"));
        }

        Ok(())
    }

    /// Validate the message.
    fn validate(&self) -> Result<()> {
        // validate protocol
        utils::validate_url(&self.descriptor.definition.protocol)?;

        // validate schemas
        for t in self.descriptor.definition.types.values() {
            if let Some(schema) = &t.schema {
                utils::validate_url(schema)?;
            }
        }

        validate_structure(&self.descriptor.definition)?;

        Ok(())
    }
}

/// Configure descriptor.
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

    /// Entry is a role record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$role")]
    pub role: Option<bool>,

    /// If $size is set, the record size in bytes must be within the limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$size")]
    pub size: Option<Range<usize>>,

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

/// Protocol tags
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct Tags {
    /// Tags required for this protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$requiredTags")]
    pub required_tags: Option<Vec<String>>,

    /// Allow tags other than those explicitly listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$allowUndefinedTags")]
    pub allow_undefined_tags: Option<bool>,

    /// Tag properties
    #[serde(flatten)]
    pub undefined_tags: BTreeMap<String, Value>,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ConfigureBuilder {
    message_timestamp: DateTime<Utc>,
    definition: Option<Definition>,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl ConfigureBuilder {
    /// Returns a new [`ConfigureBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specify the protocol's definition.
    #[must_use]
    pub fn definition(mut self, definition: Definition) -> Self {
        self.definition = Some(definition);
        self
    }

    /// The delegated grant invoked to sign on behalf of the logical author,
    /// who is the grantor of the delegated grant.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Generate the Configure message body..
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Configure> {
        // check definition has been set
        let mut definition = self.definition.ok_or_else(|| unexpected!("definition not found"))?;

        // normalize definition urls
        definition.protocol = utils::clean_url(&definition.protocol)?;
        for t in definition.types.values_mut() {
            if let Some(schema) = &t.schema {
                t.schema = Some(utils::clean_url(schema)?);
            }
        }
        validate_structure(&definition)?;

        let descriptor = ConfigureDescriptor {
            base: Descriptor {
                interface: Interface::Protocols,
                method: Method::Configure,
                message_timestamp: self.message_timestamp,
            },
            definition,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(permission_grant_id) = self.permission_grant_id {
            builder = builder.permission_grant_id(permission_grant_id);
        }
        if let Some(delegated_grant) = self.delegated_grant {
            builder = builder.delegated_grant(delegated_grant);
        }
        let authorization = builder.build(signer).await?;

        let configure = Configure {
            descriptor,
            authorization,
        };

        // TODO: move validation out of message
        schema::validate(&configure)?;

        Ok(configure)
    }
}

// Verify the structure (rule sets) of the protocol definition.
fn validate_structure(definition: &Definition) -> Result<()> {
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
        if size.min > size.max {
            return Err(unexpected!("invalid size range at '{protocol_path}'"));
        }
    }

    // validate tags schemas
    if let Some(tags) = &rule_set.tags {
        for tag in tags.undefined_tags.keys() {
            let schema = serde_json::from_str(tag)?;
            jsonschema::validator_for(&schema)
                .map_err(|e| unexpected!("tag schema validation error: {e}"))?;
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
                return Err(unexpected!("missing role {role} in action"));
            }

            // if ANY `can` actions are read-like ('read', 'query', 'subscribe')
            // then ALL read-like actions must be present
            let mut read_actions = vec![Action::Read, Action::Query, Action::Subscribe];
            read_actions.retain(|ra| action.can.contains(ra));

            // intersection of `read_actions` and `can`: it should be empty or 3
            if !read_actions.is_empty() && read_actions.len() != 3 {
                return Err(unexpected!("role {role} is missing read-like actions"));
            }
        }

        // when `who` is `anyone`, `of` cannot be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Anyone) && action.of.is_some() {
            return Err(unexpected!("`of` must not be set when `who` is \"anyone\""));
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
                return Err(unexpected!(
                    "recipient action must contain only co-update, co-delete, and co-prune",
                ));
            }
        }

        // when `who` is set to "author" then `of` must be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Author) && action.of.is_none() {
            return Err(unexpected!("`of` must be set when `who` is set to 'author'"));
        }

        // when `can` contains `update` or `delete`, it must also contain `create`
        if action.can.contains(&Action::Update) && !action.can.contains(&Action::Create) {
            return Err(unexpected!("action rule {action:?} contains 'update' but no 'create'"));
        }
        if action.can.contains(&Action::Delete) && !action.can.contains(&Action::Create) {
            return Err(unexpected!("action rule {action:?} contains 'delete' but no 'create'"));
        }

        // ensure no duplicate actors or roles in the remaining action rules
        // ie. no two action rules can have the same combination of `who` + `of` or `role`.
        for other in action_iter.clone() {
            if action.who.is_some() {
                if action.who == other.who && action.of == other.of {
                    return Err(unexpected!("an actor may only have one rule within a rule set"));
                }
            } else if action.role == other.role {
                return Err(unexpected!(
                    "more than one action rule per role {:?} not allowed within a rule set: {action:?}",
                    action.role
                ));
            }
        }
    }

    // verify nested rule sets
    for (set_name, rule_set) in &rule_set.structure {
        if !types.contains(&set_name) {
            return Err(unexpected!("rule set {set_name} is not declared as an allowed type"));
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
        return Err(unexpected!("Entry nesting depth exceeded 10 levels."));
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
