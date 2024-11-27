//! # Protocol Permissions

use crate::auth::Authorization;
use crate::permissions::{self, Grant, Request, Scope};
use crate::protocols::{
    integrity, Action, ActionRule, Actor, RuleSet, GRANT_PATH, PROTOCOL_URI, REVOCATION_PATH,
};
use crate::provider::MessageStore;
use crate::records::{self, write, Delete, Query, Read, Subscribe, Write};
use crate::store::RecordsQuery;
use crate::{forbidden, Range, Result};

/// Protocol-based authorization.
pub struct Protocol<'a> {
    protocol: &'a str,
    context_id: Option<&'a String>,
}

impl<'a> Protocol<'a> {
    /// Create a new `Protocol` instance.
    #[must_use]
    pub const fn new(protocol: &'a str) -> Self {
        Self {
            protocol,
            context_id: None,
        }
    }

    /// Context ID to use when verifying role.
    #[must_use]
    pub const fn context_id(mut self, context_id: Option<&'a String>) -> Self {
        self.context_id = context_id;
        self
    }
}

enum Record {
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
            Self::Read(read) => &read.descriptor.filter.protocol_path,
            Self::Query(query) => &query.descriptor.filter.protocol_path,
            Self::Subscribe(subscribe) => &subscribe.descriptor.filter.protocol_path,
            Self::Delete(_) => {
                unimplemented!("delete's protocol is provided by initial write record");
            }
        };

        let protocol = self.protocol()?;
        let definition = integrity::protocol_definition(owner, protocol, store).await?;

        let Some(protocol_path) = &protocol_path else {
            return Err(forbidden!("missing protocol"));
        };
        let Some(rule_set) = integrity::rule_set(protocol_path, &definition.structure) else {
            return Err(forbidden!("no rule set defined for protocol path"));
        };

        Ok(rule_set)
    }
}

impl Protocol<'_> {
    /// Protocol-based authorization for `records::Write` messages.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn permit_write(
        &self, owner: &str, write: &Write, store: &impl MessageStore,
    ) -> Result<()> {
        // get permitted roles
        let record: Record = write.into();
        let rule_set = record.rule_set(owner, store).await?;

        self.allow_role(owner, &record, &rule_set, store).await?;
        self.allow_action(owner, &record, &rule_set, store).await?;

        Ok(())
    }

    /// Protocol-based authorization for `records::Query` and `records::Subscribe`
    /// messages.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn permit_read(
        &self, owner: &str, read: &Read, store: &impl MessageStore,
    ) -> Result<()> {
        let record: Record = read.into();
        let rule_set = record.rule_set(owner, store).await?;

        self.allow_role(owner, &record, &rule_set, store).await?;
        self.allow_action(owner, &record, &rule_set, store).await?;

        Ok(())
    }

    /// Protocol-based authorization for `records::Query` and `records::Subscribe`
    /// messages.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn permit_query(
        &self, owner: &str, query: &Query, store: &impl MessageStore,
    ) -> Result<()> {
        let record: Record = query.into();
        let rule_set = record.rule_set(owner, store).await?;

        self.allow_role(owner, &record, &rule_set, store).await?;
        self.allow_action(owner, &record, &rule_set, store).await?;

        Ok(())
    }

    /// Protocol-based authorization for `records::Subscribe` messages.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn permit_subscribe(
        &self, owner: &str, subscribe: &Subscribe, store: &impl MessageStore,
    ) -> Result<()> {
        let record: Record = subscribe.into();
        let rule_set = record.rule_set(owner, store).await?;

        self.allow_role(owner, &record, &rule_set, store).await?;
        self.allow_action(owner, &record, &rule_set, store).await?;

        Ok(())
    }

    /// Protocol-based authorization for `records::Delete` messages.
    ///
    /// # Errors
    /// TODO: Document errors
    pub async fn permit_delete(
        &self, owner: &str, delete: &Delete, write: &Write, store: &impl MessageStore,
    ) -> Result<()> {
        let record: Record = write.into();
        let rule_set = record.rule_set(owner, store).await?;

        let delete: Record = delete.into();

        self.allow_role(owner, &delete, &rule_set, store).await?;
        self.allow_action(owner, &delete, &rule_set, store).await?;

        Ok(())
    }

    // Check if the incoming message is invoking a role. If so, validate the invoked role.
    async fn allow_role(
        &self, owner: &str, record: &Record, rule_set: &RuleSet, store: &impl MessageStore,
    ) -> Result<()> {
        let Some(authzn) = record.authorization() else {
            return Err(forbidden!("missing authorization"));
        };

        let author = authzn.author()?;
        let Some(protocol_role) = authzn.jws_payload()?.protocol_role else {
            return Ok(());
        };
        if !rule_set.role.unwrap_or_default() {
            return Err(forbidden!(
                "protocol path {protocol_role} does not match role record type"
            ));
        }

        let segment_count = protocol_role.split('/').count();
        if self.context_id.is_none() && segment_count > 1 {
            return Err(forbidden!("unable verify role without `context_id`"));
        }

        let mut query = RecordsQuery::new()
            .protocol(self.protocol)
            .protocol_path(&protocol_role)
            .add_recipient(author);

        // `context_id` prefix filter
        if segment_count > 0 {
            // context_id segment count is never shorter than the role path count.
            let default = String::new();
            let context_id = self.context_id.unwrap_or(&default);
            let context_id_segments: Vec<&str> = context_id.split('/').collect();
            let prefix = context_id_segments[..segment_count].join("/");

            query = query.context_id(Range::new(
                Some(prefix.to_string()),
                Some(format!("{prefix}\u{ffff}")),
            ));
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
    async fn allow_action(
        &self, owner: &str, record: &Record, rule_set: &RuleSet, store: &impl MessageStore,
    ) -> Result<()> {
        // build record chain
        let record_chain = match record {
            Record::Write(write) => {
                if write::initial_entry(owner, &write.record_id, store).await?.is_some() {
                    self.record_chain(owner, &write.record_id, store).await?
                } else if let Some(parent_id) = &write.descriptor.parent_id {
                    self.record_chain(owner, parent_id, store).await?
                } else {
                    vec![]
                }
            }
            Record::Query(_) | Record::Subscribe(_) | Record::Read(_) => Vec::new(),
            Record::Delete(delete) => {
                self.record_chain(owner, &delete.descriptor.record_id, store).await?
            }
        };

        let Some(authzn) = record.authorization() else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;
        let role = authzn.jws_payload()?.protocol_role;
        let allowed_actions = self.allowed_actions(owner, record, store).await?;
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
        &self, owner: &str, record_id: &str, store: &impl MessageStore,
    ) -> Result<Vec<Write>> {
        let mut chain = vec![];

        // keep walking up the chain from the inbound message's parent, until there
        // is no more parent
        let mut current_id = Some(record_id.to_owned());

        while let Some(record_id) = &current_id {
            let Some(initial) = write::initial_entry(owner, record_id, store).await? else {
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
        &self, owner: &str, record: &Record, store: &impl MessageStore,
    ) -> Result<Vec<Action>> {
        match record {
            Record::Write(write) => {
                if write.is_initial()? {
                    return Ok(vec![Action::Create]);
                }
                let Some(initial) = write::initial_entry(owner, &write.record_id, store).await?
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
            // Method::Read => Ok(vec![Action::Read]),
            Record::Subscribe(_) => Ok(vec![Action::Subscribe]),
            Record::Delete(delete) => {
                let Some(initial) =
                    write::initial_entry(owner, &delete.descriptor.record_id, store).await?
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
            } // Method::Configure => Err(forbidden!("configure method not allowed")),
        }
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

/// Get the scope for a permission record. If the record is a revocation, the
/// scope is fetched from the grant that is being revoked.
pub async fn fetch_scope(owner: &str, write: &Write, store: &impl MessageStore) -> Result<Scope> {
    //Result<Scope>
    if write.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
        return Err(forbidden!("unexpected protocol for permission record"));
    }
    if write.descriptor.protocol_path == Some(REVOCATION_PATH.to_string()) {
        let Some(parent_id) = &write.descriptor.parent_id else {
            return Err(forbidden!("missing parent ID for revocation record"));
        };
        let grant = permissions::fetch_grant(owner, parent_id, store).await?;
        return Ok(grant.data.scope);
    } else if write.descriptor.protocol_path == Some(GRANT_PATH.to_string()) {
        let grant = Grant::try_from(write)?;
        return Ok(grant.data.scope);
    }

    let request = Request::try_from(write)?;
    Ok(request.scope)
}
