//! # Protocol Permissions

use crate::auth::Authorization;
use crate::endpoint::Message;
use crate::protocols::{integrity, Action, ActionRule, Actor, RuleSet};
use crate::provider::MessageStore;
use crate::records::{self, Delete, Query, Subscribe, Write};
use crate::store::RecordsQuery;
use crate::{forbidden, Range, Result};

enum Record {
    Write(Write),
    Query(Query),
    Subscribe(Subscribe),
    Delete(Delete),
}

impl Record {
    fn authorization(&self) -> Authorization {
        match self {
            Self::Write(write) => write.authorization.clone(),
            Self::Delete(delete) => delete.authorization.clone(),
            Self::Query(query) => {
                let Some(authzn) = query.authorization.clone() else {
                    return Authorization::default();
                };
                authzn
            }
            Self::Subscribe(subscribe) => {
                let Some(authzn) = subscribe.authorization.clone() else {
                    return Authorization::default();
                };
                authzn
            }
        }
    }
}

/// Protocol-based authorization for `records::Write` messages.
pub async fn permit_write(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    // get permitted roles
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let definition = integrity::protocol_definition(owner, protocol, store).await?;

    // get permitted actions
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol"));
    };
    let Some(rule_set) = integrity::rule_set(protocol_path, &definition.structure) else {
        return Err(forbidden!("no rule set defined for protocol path"));
    };

    verify_role(owner, write, &rule_set, protocol, write.context_id.clone(), store).await?;
    verify_action(owner, &Record::Write(write.clone()), &rule_set, store).await?;

    Ok(())
}

/// Protocol-based authorization for `records::Query` and `records::Subscribe`
/// messages.
pub async fn permit_read(owner: &str, query: &Query, store: &impl MessageStore) -> Result<()> {
    let filter = &query.descriptor.filter;

    // get permitted roles
    let Some(protocol) = &filter.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let definition = integrity::protocol_definition(owner, protocol, store).await?;

    // get permitted actions
    let Some(protocol_path) = &filter.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(rule_set) = integrity::rule_set(protocol_path, &definition.structure) else {
        return Err(forbidden!("no rule set defined for protocol path"));
    };

    verify_role(owner, query, &rule_set, protocol, filter.context_id.clone(), store).await?;
    verify_action(owner, &Record::Query(query.clone()), &rule_set, store).await?;

    Ok(())
}

pub async fn permit_subscribe(
    owner: &str, subscribe: &Subscribe, store: &impl MessageStore,
) -> Result<()> {
    let filter = &subscribe.descriptor.filter;

    // get permitted roles
    let Some(protocol) = &filter.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let definition = integrity::protocol_definition(owner, protocol, store).await?;

    // get permitted actions
    let Some(protocol_path) = &filter.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(rule_set) = integrity::rule_set(protocol_path, &definition.structure) else {
        return Err(forbidden!("no rule set defined for protocol path"));
    };

    verify_role(owner, subscribe, &rule_set, protocol, filter.context_id.clone(), store).await?;
    verify_action(owner, &Record::Subscribe(subscribe.clone()), &rule_set, store).await?;

    Ok(())
}

/// Protocol-based authorization for `records::Delete` messages.
pub async fn permit_delete(
    owner: &str, delete: &Delete, write: &Write, store: &impl MessageStore,
) -> Result<()> {
    // get permitted roles
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let definition = integrity::protocol_definition(owner, protocol, store).await?;

    // get permitted actions
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol"));
    };
    let Some(rule_set) = integrity::rule_set(protocol_path, &definition.structure) else {
        return Err(forbidden!("no rule set defined for protocol path"));
    };

    verify_role(owner, delete, &rule_set, protocol, write.context_id.clone(), store).await?;
    verify_action(owner, &Record::Delete(delete.clone()), &rule_set, store).await?;

    Ok(())
}

// Check if the incoming message is invoking a role. If so, validate the invoked role.
async fn verify_role(
    owner: &str, msg: &impl Message, rule_set: &RuleSet, protocol: &str,
    context_id: Option<String>, store: &impl MessageStore,
) -> Result<()> {
    let Some(authzn) = msg.authorization() else {
        return Err(forbidden!("missing authorization"));
    };

    let author = authzn.author()?;
    let Some(protocol_role) = authzn.jws_payload()?.protocol_role else {
        return Ok(());
    };
    if !rule_set.role.unwrap_or_default() {
        return Err(forbidden!("protocol path {protocol_role} does not match role record type"));
    }

    let segment_count = protocol_role.split('/').count();
    if context_id.is_none() && segment_count > 1 {
        return Err(forbidden!("unable verify role without `context_id`"));
    }

    let mut query =
        RecordsQuery::new().protocol(protocol).protocol_path(&protocol_role).add_recipient(author);

    // `context_id` prefix filter
    if segment_count > 0 {
        // context_id segment count is never shorter than the role path count.
        let context_id = context_id.unwrap_or_default();
        let context_id_segments: Vec<&str> = context_id.split('/').collect();
        let prefix = context_id_segments[..segment_count].join("/");

        query = query
            .context_id(Range::new(Some(prefix.to_string()), Some(format!("{prefix}\u{ffff}"))));
    }
    // fetch the invoked role record
    let (records, _) = store.query(owner, &query.build()).await?;

    if records.is_empty() {
        return Err(forbidden!("unable to find records for {protocol_role}"));
    }

    Ok(())
}

// Verifies the given message is authorized by one of the action rules in the
// given protocol rule set.
async fn verify_action(
    owner: &str, record: &Record, rule_set: &RuleSet, store: &impl MessageStore,
) -> Result<()> {
    // build record chain
    let record_chain = match record {
        Record::Write(write) => {
            let messages = records::existing_entries(owner, &write.record_id, store).await?;
            let (initial, _) = records::earliest_and_latest(&messages).await?;

            if initial.is_some() {
                record_chain(owner, &write.record_id, store).await?
            } else if let Some(parent_id) = &write.descriptor.parent_id {
                record_chain(owner, parent_id, store).await?
            } else {
                vec![]
            }
        }
        Record::Query(_) | Record::Subscribe(_) => Vec::new(),
        Record::Delete(delete) => record_chain(owner, &delete.descriptor.record_id, store).await?,
    };

    let author = record.authorization().author()?;
    let role = record.authorization().jws_payload()?.protocol_role;
    let allowed_actions = allowed_actions(owner, record, store).await?;
    let Some(action_rules) = &rule_set.actions else {
        return Err(forbidden!("no rule defined for action"));
    };

    // find a rule that authorizes the incoming message
    for rule in action_rules {
        if !rule.can.iter().any(|action| allowed_actions.contains(action)) {
            continue;
        }
        if rule.who == Some(Actor::Anyone) {
            return Ok(());
        }

        // validate role
        if role.is_some() {
            if rule.role == role {
                return Ok(());
            }
            continue;
        }

        // validate actor
        if rule.who == Some(Actor::Recipient) && rule.of.is_none() {
            let message = if let Record::Write(write) = &record {
                write
            } else {
                // the incoming message must be a `RecordsDelete` because only
                // `co-update`, `co-delete`, `co-prune` are allowed recipient actions,
                &record_chain[record_chain.len() - 1]
            };

            if message.descriptor.recipient.as_ref() == Some(&author) {
                return Ok(());
            }
            continue;
        }

        // is actor allowed by the current action rule?
        if check_actor(&author, rule, &record_chain)? {
            return Ok(());
        }
    }

    Err(forbidden!("action not permitted"))
}

// Constructs the chain of EXISTING records in the datastore where the first
// record is the root initial `records::Write` of the record chain and last
// record is the initial `records::Write` of the descendant record specified.
async fn record_chain(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Vec<Write>> {
    let mut chain = vec![];

    // keep walking up the chain from the inbound message's parent, until there
    // is no more parent
    let mut current_id = Some(record_id.to_owned());

    while let Some(record_id) = &current_id {
        let messages = records::existing_entries(owner, record_id, store).await?;
        let (initial, _) = records::earliest_and_latest(&messages).await?;

        let Some(initial) = initial else {
            return Err(forbidden!(
                "no parent found with ID {record_id} when constructing record chain"
            ));
        };

        chain.push(initial.clone());
        current_id.clone_from(&initial.descriptor.parent_id);
    }

    // root record first
    chain.reverse();
    Ok(chain)
}

// Match `Action`s that authorize the incoming message.
//
// N.B. keep in mind an author's 'write' access may be revoked.
async fn allowed_actions(
    owner: &str, record: &Record, store: &impl MessageStore,
) -> Result<Vec<Action>> {
    match record {
        Record::Write(write) => {
            if write.is_initial()? {
                return Ok(vec![Action::Create]);
            }

            let messages = records::existing_entries(owner, &write.record_id, store).await?;
            let (initial, _) = records::earliest_and_latest(&messages).await?;

            let Some(initial) = initial else {
                return Ok(Vec::new());
            };
            if write.authorization.author()? == initial.authorization.author()? {
                return Ok(vec![Action::CoUpdate, Action::Update]);
            }

            Ok(vec![Action::CoUpdate])
        }
        Record::Query(_) => Ok(vec![Action::Query]),
        // Method::Read => Ok(vec![Action::Read]),
        Record::Subscribe(_) => Ok(vec![Action::Subscribe]),
        Record::Delete(delete) => {
            let messages =
                records::existing_entries(owner, &delete.descriptor.record_id, store).await?;
            let (initial, _) = records::earliest_and_latest(&messages).await?;
            let Some(initial) = initial else {
                return Ok(Vec::new());
            };

            let mut actions = vec![];
            let author = delete.authorization.author()?;
            let initial_author = initial.authorization.author()?;

            if delete.descriptor.prune {
                actions.push(Action::CoPrune);
                if author == initial_author {
                    actions.push(Action::Prune);
                }
            }

            actions.push(Action::CoDelete);
            if author == initial_author {
                actions.push(Action::Delete);
            }

            Ok(actions)
        } // Method::Configure => Err(forbidden!("configure method not allowed")),
    }
}

// Checks for a match with the `who` rule in record chain.
fn check_actor(author: &str, action_rule: &ActionRule, record_chain: &[Write]) -> Result<bool> {
    // find a message with matching protocolPath
    let ancestor =
        record_chain.iter().find(|write| write.descriptor.protocol_path == action_rule.of);
    let Some(ancestor) = ancestor else {
        // reaching this block means there is an issue with the protocol definition
        // this check should happen `protocols::Configure`
        return Ok(false);
    };
    if action_rule.who == Some(Actor::Recipient) {
        return Ok(Some(author.to_owned()) == ancestor.descriptor.recipient);
    }
    Ok(author == ancestor.authorization.author()?)
}
