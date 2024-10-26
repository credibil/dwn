//! # Protocols

pub mod configure;
pub mod query;

use anyhow::{anyhow, Result};
use chrono::Utc;

pub use self::configure::{
    Action, Actor, Configure, ConfigureDescriptor, Definition, RuleSet, Type,
};
pub use self::query::{Query, Reply as QueryReply};
use crate::auth::AuthorizationBuilder;
use crate::provider::Signer;
use crate::records::Write;
use crate::service::Message;
use crate::{cid, utils, Descriptor, Interface, Method};

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ConfigureBuilder {
    message_timestamp: Option<String>,
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
            message_timestamp: Some(Utc::now().to_rfc3339()),
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
    pub fn permission_grant_id(mut self, permission_grant_id: String) -> Self {
        self.permission_grant_id = Some(permission_grant_id);
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Configure> {
        // check definition has been set
        let mut definition = self.definition.ok_or_else(|| anyhow!("definition not found"))?;

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
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::compute(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(signer).await?;

        let configure = Configure {
            descriptor,
            authorization,
        };

        // TODO: move validation out of message
        let message = Message::ProtocolsConfigure(configure.clone());
        message.validate_schema()?;

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
            return Err(anyhow!("invalid size range at '{protocol_path}'"));
        }
    }

    // validate tags schemas
    if let Some(tags) = &rule_set.tags {
        for tag in tags.undefined_tags.keys() {
            let schema = serde_json::from_str(tag)?;
            jsonschema::validator_for(&schema)
                .map_err(|e| anyhow!("tag schema validation error: {e}"))?;
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
                return Err(anyhow!("missing role {role} in action for {protocol_path}"));
            }

            // all read-like ('read', 'query', 'subscribe') `can` actions must be present
            let allowed = [Action::Read, Action::Query, Action::Subscribe];
            if !allowed.iter().all(|ra| action.can.contains(ra)) {
                return Err(anyhow!("role {role} missing read-like action(s) for {protocol_path}"));
            }
        }

        // when `who` is `anyone`, `of` cannot be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Anyone) && action.of.is_some() {
            return Err(anyhow!(
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
                return Err(anyhow!(
                    "recipient action must contain only co-update, co-delete, and co-prune"
                ));
            }
        }

        // when `who` is set to "author" then `of` must be set
        if action.who.as_ref().is_some_and(|w| w == &Actor::Author) && action.of.is_none() {
            return Err(anyhow!("`of` must be set when `who` is set to 'author'"));
        }

        // when `can` contains `update` or `delete`, it must also contain `create`
        if action.can.contains(&Action::Update) && !action.can.contains(&Action::Create) {
            return Err(anyhow!("action rule {action:?} contains 'update' but no 'create'"));
        }
        if action.can.contains(&Action::Delete) && !action.can.contains(&Action::Create) {
            return Err(anyhow!("action rule {action:?} contains 'delete' but no 'create'"));
        }

        // ensure no duplicate actors or roles in the remaining action rules
        // ie. no two action rules can have the same combination of `who` + `of` or `role`.

        // let other_iter = action_iter.clone();
        for other in action_iter.clone() {
            if action.who.is_some() {
                if action.who == other.who && action.of == other.of {
                    return Err(anyhow!(
                        "more than one action rule per actor {:?} of {:?} not allowed within a rule set: {action:?}", action.who, action.of
                    ));
                }
            } else if action.role == other.role {
                return Err(anyhow!(
                    "more than one action rule per role {:?} not allowed within a rule set: {action:?}",action.role
                ));
            }
        }
    }

    // verify nested rule sets
    for (set_name, rule_set) in &rule_set.nested {
        if !types.contains(&set_name) {
            return Err(anyhow!("rule set {set_name} is not declared as an allowed type"));
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
        return Err(anyhow!("Record nesting depth exceeded 10 levels."));
    }

    for (rule_name, rule_set) in &rule_set.nested {
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
