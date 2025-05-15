//! # Authorizer-based Authorizers
//!
//! Authorizer-based permissions are a way to configure access control for DWN
//! users based on the protocol used in their interactions (messages).
//!
//! This module provides the logic to enforce these permissions.

use crate::authorization::Authorization;
use crate::forbidden;
use crate::handlers::{Result, protocols_configure, records_write};
use crate::interfaces::protocols::{Action, ActionRule, Actor, RuleSet};
use crate::interfaces::records::{Delete, Query, Read, RecordsFilter, Subscribe, Write};
use crate::provider::MessageStore;
use crate::store::RecordsQueryBuilder;

/// [`Authorizer`] holds protocol-related information required during the process
/// of verifying an incoming message's protocol-based authorization.
pub struct Authorizer<'a> {
    protocol: &'a str,
    context_id: Option<&'a String>,
    initial_write: Option<&'a Write>,
}

// TODO: use typestate builder pattern to enforce correct usage for each record
// type and reduce args passed to permit_* methods
impl<'a> Authorizer<'a> {
    /// Create a new `Authorizer` instance for the specified protocol.
    #[must_use]
    pub const fn new(protocol: &'a str) -> Self {
        Self {
            protocol,
            context_id: None,
            initial_write: None,
        }
    }

    /// The context ID to use when verifying a role.
    #[must_use]
    pub const fn context_id(mut self, context_id: Option<&'a String>) -> Self {
        self.context_id = context_id;
        self
    }

    /// The initial Write to use with `permit_read` and `permit_delete`.
    #[must_use]
    pub const fn initial_write(mut self, initial_write: &'a Write) -> Self {
        self.initial_write = Some(initial_write);
        self
    }
}

impl Authorizer<'_> {
    /// Authorizer-based authorization for [`Write`] messages.
    pub async fn permit_write(
        &self, owner: &str, write: impl Into<Record>, store: &impl MessageStore,
    ) -> Result<()> {
        let record = write.into();
        self.permit_role(owner, &record, store).await?;
        self.permit_action(owner, &record, store).await
    }

    /// Authorizer-based authorization for [`Query`] and [`Read`] messages.
    pub async fn permit_read(
        &self, owner: &str, read: impl Into<Record>, store: &impl MessageStore,
    ) -> Result<()> {
        let record = read.into();
        self.permit_role(owner, &record, store).await?;
        self.permit_action(owner, &record, store).await
    }

    /// Authorizer-based authorization for [`Query`] messages.
    pub async fn permit_query(
        &self, owner: &str, query: impl Into<Record>, store: &impl MessageStore,
    ) -> Result<()> {
        let record = query.into();
        self.permit_role(owner, &record, store).await?;
        self.permit_action(owner, &record, store).await
    }

    /// Authorizer-based authorization for [`Subscribe`] messages.
    pub async fn permit_subscribe(
        &self, owner: &str, subscribe: impl Into<Record>, store: &impl MessageStore,
    ) -> Result<()> {
        let record = subscribe.into();
        self.permit_role(owner, &record, store).await?;
        self.permit_action(owner, &record, store).await
    }

    /// Authorizer-based authorization for [`Delete`] messages.
    pub async fn permit_delete(
        &self, owner: &str, delete: impl Into<Record>, store: &impl MessageStore,
    ) -> Result<()> {
        let record = delete.into();
        self.permit_role(owner, &record, store).await?;
        self.permit_action(owner, &record, store).await
    }
}

impl Authorizer<'_> {
    // Check if the incoming message is invoking a role. If so, verify the invoked role.
    async fn permit_role(
        &self, owner: &str, record: &Record, store: &impl MessageStore,
    ) -> Result<()> {
        let Some(authzn) = record.authorization() else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;
        let Some(protocol_role) = authzn.payload()?.protocol_role else {
            return Ok(());
        };

        let definition = protocols_configure::definition(owner, self.protocol, store).await?;
        let Some(role_rule_set) =
            protocols_configure::rule_set(&protocol_role, &definition.structure)
        else {
            return Err(forbidden!("no rule set defined for invoked role"));
        };
        if !role_rule_set.role.unwrap_or_default() {
            return Err(forbidden!("protocol path does not match role record type"));
        }

        // build query to fetch the invoked role record
        let mut filter = RecordsFilter::new()
            .protocol(self.protocol)
            .protocol_path(&protocol_role)
            .add_recipient(author);

        // `context_id` filter
        let role_segments = protocol_role.split('/').count() - 1;
        if role_segments > 0 {
            let Some(context_id) = self.context_id else {
                return Err(forbidden!("unable verify role without a `context_id`"));
            };

            // get parent context ID
            if let Some((parent, _)) = context_id.rsplit_once('/') {
                filter = filter.context_id(parent);
            } else {
                filter = filter.context_id(context_id);
            }
        }

        // check the invoked role record exists
        let query = RecordsQueryBuilder::new().add_filter(filter).build();
        let (entries, _) = store.query(owner, &query).await?;
        if entries.is_empty() {
            return Err(forbidden!("unable to find record for role"));
        }

        Ok(())
    }

    // Verifies the given message is authorized by one of the action rules in the
    // given protocol rule set.
    async fn permit_action(
        &self, owner: &str, record: &Record, store: &impl MessageStore,
    ) -> Result<()> {
        let rule_set = if let Some(write) = self.initial_write {
            let write_record: Record = write.into();
            write_record.rule_set(owner, store).await?
        } else {
            record.rule_set(owner, store).await?
        };

        // build chain of ancestor records
        let ancestor_chain = match record {
            Record::Write(write) => {
                // if write::initial_write(owner, &write.record_id, store).await?.is_some() {
                if !write.is_initial()? {
                    self.ancestor_chain(owner, &write.record_id, store).await?
                } else if let Some(parent_id) = &write.descriptor.parent_id {
                    self.ancestor_chain(owner, parent_id, store).await?
                } else {
                    vec![]
                }
            }
            Record::Delete(delete) => {
                self.ancestor_chain(owner, &delete.descriptor.record_id, store).await?
            }
            Record::Query(_) | Record::Subscribe(_) | Record::Read(_) => Vec::new(),
        };

        let Some(authzn) = record.authorization() else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;
        let invoked_role = authzn.payload()?.protocol_role;
        let permitted_actions = self.permitted_actions(owner, record, store).await?;
        let Some(action_rules) = &rule_set.actions else {
            return Err(forbidden!("no rule defined for action"));
        };

        // find a rule that authorizes the incoming message
        for rule in action_rules {
            if !rule.can.iter().any(|action| permitted_actions.contains(action)) {
                continue;
            }
            if rule.who == Some(Actor::Anyone) {
                return Ok(());
            }
            if invoked_role.is_some() {
                if rule.role == invoked_role {
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
                    &ancestor_chain[ancestor_chain.len() - 1]
                };

                if message.descriptor.recipient.as_ref() == Some(&author) {
                    return Ok(());
                }
                continue;
            }

            // is actor allowed by the current action rule?
            if permit_actor(&author, rule, &ancestor_chain)? {
                return Ok(());
            }
        }

        Err(forbidden!("action not permitted"))
    }

    // Constructs a chain of ancestor `initial_write` records starting from
    // `descendant_id` and working backwards.
    //
    // e.g. root_initial_write <- ... <- descendant_initial_write
    // => vec![root_initial_write, ...,descendant_initial_write]
    async fn ancestor_chain(
        &self, owner: &str, descendant_id: &str, store: &impl MessageStore,
    ) -> Result<Vec<Write>> {
        let mut ancestors = vec![];
        let mut current_id = Some(descendant_id.to_owned());

        // walk up the ancestor tree until no parent
        while let Some(record_id) = &current_id {
            let Some(initial) = records_write::initial_write(owner, record_id, store).await? else {
                return Err(forbidden!("no parent record found"));
            };
            ancestors.push(initial.clone());
            current_id.clone_from(&initial.descriptor.parent_id);
        }

        // order from root to descendant
        ancestors.reverse();
        Ok(ancestors)
    }

    // Match `Action`s that authorize the incoming message.
    // N.B. keep in mind an author's 'write' access may be revoked.
    async fn permitted_actions(
        &self, owner: &str, record: &Record, store: &impl MessageStore,
    ) -> Result<Vec<Action>> {
        match record {
            Record::Write(write) => {
                if write.is_initial()? {
                    return Ok(vec![Action::Create]);
                }
                let Some(initial) =
                    records_write::initial_write(owner, &write.record_id, store).await?
                else {
                    return Ok(Vec::new());
                };
                if write.authorization.author()? == initial.authorization.author()? {
                    return Ok(vec![Action::CoUpdate, Action::Update]);
                }
                Ok(vec![Action::CoUpdate])
            }
            Record::Read(_) => Ok(vec![Action::Read]),
            Record::Query(_) => Ok(vec![Action::Query]),
            Record::Subscribe(_) => Ok(vec![Action::Subscribe]),
            Record::Delete(delete) => {
                let Some(initial) =
                    records_write::initial_write(owner, &delete.descriptor.record_id, store)
                        .await?
                else {
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
            }
        }
    }
}

// Checks for a match with the `who` rule in record chain.
fn permit_actor(author: &str, action_rule: &ActionRule, ancestor_chain: &[Write]) -> Result<bool> {
    // find a message with matching protocolPath
    let ancestor =
        ancestor_chain.iter().find(|write| write.descriptor.protocol_path == action_rule.of);
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

/// Wrap Records interface messages into a common enum to allow for reuse of
/// authorization checks.
pub enum Record {
    Write(Write),
    Read(Read),
    Query(Query),
    Subscribe(Subscribe),
    Delete(Delete),
}

impl From<&Write> for Record {
    fn from(write: &Write) -> Self {
        Self::Write(write.clone())
    }
}

impl From<&Read> for Record {
    fn from(read: &Read) -> Self {
        Self::Read(read.clone())
    }
}

impl From<&Query> for Record {
    fn from(query: &Query) -> Self {
        Self::Query(query.clone())
    }
}

impl From<&Subscribe> for Record {
    fn from(subscribe: &Subscribe) -> Self {
        Self::Subscribe(subscribe.clone())
    }
}

impl From<&Delete> for Record {
    fn from(delete: &Delete) -> Self {
        Self::Delete(delete.clone())
    }
}

impl Record {
    const fn authorization(&self) -> Option<&Authorization> {
        match self {
            Self::Write(write) => Some(&write.authorization),
            Self::Read(read) => read.authorization.as_ref(),
            Self::Delete(delete) => Some(&delete.authorization),
            Self::Query(query) => query.authorization.as_ref(),
            Self::Subscribe(subscribe) => subscribe.authorization.as_ref(),
        }
    }

    fn protocol(&self) -> Result<&str> {
        let protocol = match self {
            Self::Write(write) => &write.descriptor.protocol,
            Self::Read(read) => &read.descriptor.filter.protocol,
            Self::Query(query) => &query.descriptor.filter.protocol,
            Self::Subscribe(subscribe) => &subscribe.descriptor.filter.protocol,
            Self::Delete(_) => {
                unimplemented!("delete's protocol is provided by initial write record");
            }
        };

        let Some(protocol) = protocol else {
            return Err(forbidden!("missing protocol"));
        };
        Ok(protocol)
    }

    async fn rule_set(&self, owner: &str, store: &impl MessageStore) -> Result<RuleSet> {
        let protocol_path = match self {
            Self::Write(write) => &write.descriptor.protocol_path,
            Self::Query(query) => &query.descriptor.filter.protocol_path,
            Self::Subscribe(subscribe) => &subscribe.descriptor.filter.protocol_path,
            Self::Read(_) | Self::Delete(_) => {
                unimplemented!("protocol is provided by initial write record");
            }
        };

        let Some(protocol_path) = &protocol_path else {
            return Err(forbidden!("missing protocol"));
        };
        let protocol = self.protocol()?;
        let definition = protocols_configure::definition(owner, protocol, store).await?;
        let Some(rule_set) = protocols_configure::rule_set(protocol_path, &definition.structure)
        else {
            return Err(forbidden!("invalid protocol path"));
        };
        Ok(rule_set)
    }
}
