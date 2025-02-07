//! # Protocols Configure
//!
//! The protocols configure endpoint handles `ProtocolsConfigure` messages —
//! requests to write to [`Configure`] records to the DWN's [`MessageStore`].

use std::collections::{BTreeMap, HashMap};

use chrono::SecondsFormat::Micros;
use http::StatusCode;

use crate::authorization::Authorization;
use crate::endpoint::{Message, Reply, Status};
use crate::interfaces::protocols::{Action, Actor, Configure, ConfigureReply, Definition, RuleSet};
use crate::interfaces::{Descriptor, MessageType};
use crate::provider::{EventLog, EventStream, MessageStore, Provider};
use crate::store::Entry;
use crate::utils::cid;
use crate::{Error, Result, forbidden, grants, unexpected, utils};

/// Handle — or process — a [`Configure`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to save the [`Configure`] message.
pub async fn handle(
    owner: &str, configure: Configure, provider: &impl Provider,
) -> Result<Reply<ConfigureReply>> {
    configure.authorize(owner, provider).await?;

    // validate the message
    configure.validate()?;

    // find any matching protocol entries
    let results = super::fetch_config(
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
        if latest_ts == configure_ts && latest.cid()? > configure.cid()? {
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

impl TryFrom<Entry> for Configure {
    type Error = crate::Error;

    fn try_from(record: Entry) -> Result<Self> {
        match record.message {
            MessageType::Configure(configure) => Ok(configure),
            _ => Err(unexpected!("expected `ProtocolsConfigure` message")),
        }
    }
}

impl Configure {
    /// Build flattened indexes for the write message.
    #[must_use]
    pub(crate) fn build_indexes(&self) -> HashMap<String, String> {
        let mut indexes = HashMap::new();
        indexes.insert("interface".to_string(), self.descriptor.base.interface.to_string());
        indexes.insert("method".to_string(), self.descriptor.base.method.to_string());
        indexes.insert("protocol".to_string(), self.descriptor.definition.protocol.clone());
        indexes.insert("published".to_string(), self.descriptor.definition.published.to_string());
        indexes.insert(
            "messageTimestamp".to_string(),
            self.descriptor.base.message_timestamp.to_rfc3339_opts(Micros, true),
        );
        indexes
    }

    /// Check message has sufficient privileges.
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;

        if authzn.author()? == owner {
            return Ok(());
        }

        // permission grant
        let Some(grant_id) = &authzn.payload()?.permission_grant_id else {
            return Err(forbidden!("author has no grant"));
        };
        let grant = grants::fetch_grant(owner, grant_id, store).await?;
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
        utils::uri::validate(&self.descriptor.definition.protocol)?;

        // validate schemas
        for t in self.descriptor.definition.types.values() {
            if let Some(schema) = &t.schema {
                utils::uri::validate(schema)?;
            }
        }

        validate_structure(&self.descriptor.definition)?;

        Ok(())
    }
}

/// Verify the structure (rule sets) of the protocol definition.
pub fn validate_structure(definition: &Definition) -> Result<()> {
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
            return Err(unexpected!("invalid size range"));
        }
    }

    // validate tags schemas
    if let Some(tags) = &rule_set.tags {
        for tag in tags.undefined.keys() {
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
