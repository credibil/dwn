//! # Configure
//!
//! Decentralized Web Node messaging framework.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::jwk::PublicKeyJwk;

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::messages::Event;
use crate::permissions::ScopeType;
use crate::protocols::query::{self, Filter};
use crate::provider::{EventLog, EventStream, MessageStore, Provider, Signer};
use crate::records::{SizeRange, Write};
use crate::service::{Context, Message, MessageRecord, Messages};
use crate::{
     schema, unexpected, utils, Descriptor, Interface, Method, Result, Status,
};
use crate::data_stream::cid;

/// Process query message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(
    owner: &str, configure: Configure, provider: &impl Provider,
) -> Result<ConfigureReply> {
    let mut ctx = Context::new(owner);
    Message::validate(&configure, &mut ctx, provider).await?;
    configure.authorize(&ctx, provider).await?;

    // find any matching protocol entries
    let filter = Filter {
        protocol: configure.descriptor.definition.protocol.clone(),
    };
    let results = query::fetch_config(&ctx.owner, Some(filter), provider).await?;

    // determine if incoming message is the latest
    let is_latest = if let Some(existing) = &results {
        // find latest matching protocol entry
        let timestamp = &configure.descriptor.base.message_timestamp;
        let (is_latest, latest) = existing.iter().fold((true, &configure), |(_, _), e| {
            if &e.descriptor.base.message_timestamp > timestamp {
                (false, e)
            } else {
                (true, &configure)
            }
        });

        // delete all entries except the most recent
        let latest_ts = latest.descriptor.base.message_timestamp.unwrap_or_default();
        for e in existing {
            let current_ts = e.descriptor.base.message_timestamp.unwrap_or_default();
            if current_ts.cmp(&latest_ts) == Ordering::Less {
                let cid = cid::from_value(&e)?;
                MessageStore::delete(provider, &ctx.owner, &cid).await?;
                EventLog::delete(provider, &ctx.owner, &cid).await?;
            }
        }
        is_latest
    } else {
        true
    };

    if !is_latest {
        return Err(unexpected!("message is not the latest"));
    }

    // save the incoming message
    let message = MessageRecord::from(&configure);
    MessageStore::put(provider, &ctx.owner, &message).await?;

    let event = Event {
        message_cid: configure.cid()?,
        base: configure.descriptor.base.clone(),
        protocol: Some(configure.descriptor.definition.protocol.clone()),
    };
    EventLog::append(provider, &ctx.owner, &event).await?;
    EventStream::emit(provider, &ctx.owner, &event).await?;

    Ok(ConfigureReply {
        status: Status {
            code: StatusCode::ACCEPTED.as_u16(),
            detail: None,
        },
        message: configure,
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

impl Message for Configure {
    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }
}

/// Configure reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigureReply {
    /// Status message to accompany the reply.
    pub status: Status,

    #[serde(flatten)]
    message: Configure,
}

impl From<Configure> for MessageRecord {
    fn from(configure: Configure) -> Self {
        Self {
            inner: Messages::ProtocolsConfigure(configure),
            indexes: Map::new(),
        }
    }
}

impl From<&Configure> for MessageRecord {
    fn from(configure: &Configure) -> Self {
        Self {
            inner: Messages::ProtocolsConfigure(configure.clone()),
            indexes: Map::new(),
        }
    }
}

impl TryFrom<MessageRecord> for Configure {
    type Error = crate::Error;

    fn try_from(message: MessageRecord) -> Result<Self> {
        match message.inner {
            Messages::ProtocolsConfigure(configure) => Ok(configure),
            Messages::RecordsWrite(_) => Err(unexpected!("expected `ProtocolsConfigure` message")),
        }
    }
}

impl Configure {
    /// Check message has sufficient privileges.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn authorize(&self, ctx: &Context, provider: &impl Provider) -> Result<()> {
        // authorize the author-delegate who signed the message
        if let Some(delegated) = &self.authorization.author_delegated_grant {
            let grant = delegated.to_grant()?;
            grant
                .verify(
                    &self.authorization.author()?,
                    &self.authorization.signer()?,
                    &self.descriptor.base,
                    provider,
                )
                .await?;
        }

        if self.authorization.author()? == ctx.owner {
            return Ok(());
        }

        let grant = ctx.grant.as_ref().ok_or_else(|| unexpected!("missing grant"))?;

        // when the grant scope does not specify a protocol, it is an unrestricted grant
        let ScopeType::Protocols { protocol } = &grant.data.scope.scope_type else {
            return Err(unexpected!("missing protocol in grant scope"));
        };
        let Some(protocol) = &protocol else {
            return Ok(());
        };

        if protocol != &self.descriptor.definition.protocol {
            return Err(unexpected!(" message protocol does not match grant protocol"));
        }

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
#[derive(Clone, Debug, Deserialize, Serialize)]
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

    /// Record is a role record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$role")]
    pub role: Option<bool>,

    /// If $size is set, the record size in bytes must be within the limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$size")]
    pub size: Option<SizeRange>,

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
    message_timestamp: Option<DateTime<Utc>>,
    definition: Option<Definition>,
    delegated_grant: Option<Write>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl ConfigureBuilder {
    /// Returns a new [`ConfigureBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Some(Utc::now()),
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
    pub fn delegated_grant(mut self, delegated_grant: Write) -> Self {
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
    /// TODO: Add errors
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
        verify_structure(&definition)?;

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
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
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

fn verify_structure(definition: &Definition) -> Result<()> {
    let keys = definition.types.keys().collect::<Vec<&String>>();

    // validate the entire rule set
    for rule_set in definition.structure.values() {
        let roles = role_paths("", rule_set, vec![])?;
        verify_rule_set(rule_set, "", &keys, &roles)?;
    }

    Ok(())
}

// Validates a rule set structure, recursively validating nested rule sets.
fn verify_rule_set(
    rule_set: &RuleSet, protocol_path: &str, types: &Vec<&String>, roles: &Vec<String>,
) -> Result<()> {
    // validate $size
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
        // for action in rule_set.actions.as_ref().unwrap_or(&Vec::new()) {
        // validate action's `role` property, if exists.
        if let Some(role) = &action.role {
            // role must contain valid protocol paths to a role record
            if !roles.contains(role) {
                return Err(unexpected!("missing role {role} in action for {protocol_path}"));
            }

            // all read-like ('read', 'query', 'subscribe') `can` actions must be present
            let allowed = [Action::Read, Action::Query, Action::Subscribe];
            if !allowed.iter().all(|ra| action.can.contains(ra)) {
                return Err(unexpected!(
                    "role {role} missing read-like action(s) for {protocol_path}"
                ));
            }
        }

        // when `who` is `anyone`, `of` cannot be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Anyone) && action.of.is_some() {
            return Err(unexpected!(
                "`of` must not be set when `who` is \"anyone\" for {protocol_path}"
            ));
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

        // let other_iter = action_iter.clone();
        for other in action_iter.clone() {
            if action.who.is_some() {
                if action.who == other.who && action.of == other.of {
                    return Err(unexpected!(
                        "more than one action rule per actor {:?} of {:?} not allowed within a rule set: {action:?}", action.who, action.of
                    ));
                }
            } else if action.role == other.role {
                return Err(unexpected!(
                    "more than one action rule per role {:?} not allowed within a rule set: {action:?}",action.role
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
        verify_rule_set(rule_set, protocol_path, types, roles)?;
    }

    Ok(())
}

// Parses the given rule set hierarchy to get all the role protocol paths.
fn role_paths(protocol_path: &str, rule_set: &RuleSet, roles: Vec<String>) -> Result<Vec<String>> {
    // restrict to max depth of 10 levels
    if protocol_path.split('/').count() > 10 {
        return Err(unexpected!("Record nesting depth exceeded 10 levels."));
    }

    for (rule_name, rule_set) in &rule_set.structure {
        let protocol_path = if protocol_path.is_empty() {
            rule_name
        } else {
            &format!("{protocol_path}/{rule_name}")
        };

        let mut roles = roles.clone();
        if rule_set.role.is_some() {
            roles.push(protocol_path.to_string());
        } else {
            role_paths(protocol_path, rule_set, roles)?;
        }
    }

    Ok(roles)
}
