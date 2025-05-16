//! # Protocols Configure
//!
//! The protocols configure endpoint handles `ProtocolsConfigure` messages —
//! requests to write to [`Configure`] records to the DWN's [`MessageStore`].

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use chrono::SecondsFormat::Micros;
use http::StatusCode;

use crate::authorization::Authorization;
use crate::handlers::{Body, Error, Handler, Request, Response, Result, verify_grant};
use crate::interfaces::protocols::{
    self, Action, ActionRule, Actor, Configure, ConfigureReply, Definition, PROTOCOL_URI,
    ProtocolType, RuleSet, Size,
};
use crate::interfaces::{Descriptor, Document};
use crate::provider::{EventLog, EventStream, MessageStore, Provider};
use crate::store::Storable;
use crate::utils::cid;
use crate::{bad, forbidden, store, utils};

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

/// Handle — or process — a [`Configure`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to save the [`Configure`] message.
async fn handle(
    owner: &str, provider: &impl Provider, configure: Configure,
) -> Result<Response<ConfigureReply>> {
    configure.authorize(owner, provider).await?;

    // validate the message
    configure.validate()?;

    // find any matching protocol entries
    let results =
        fetch_config(owner, Some(configure.descriptor.definition.protocol.clone()), provider)
            .await?;

    // determine incoming message is the latest
    if let Some(existing) = &results {
        let Some(latest) = existing.iter().max_by(|a, b| {
            a.descriptor.base.message_timestamp.cmp(&b.descriptor.base.message_timestamp)
        }) else {
            return Err(bad!("no matching protocol entries found"));
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
    MessageStore::put(provider, owner, &configure).await?;
    EventLog::append(provider, owner, &configure).await?;
    EventStream::emit(provider, owner, &Document::Configure(configure.clone())).await?;

    Ok(Response {
        status: StatusCode::ACCEPTED,
        headers: None,
        body: ConfigureReply { message: configure },
    })
}

impl<P: Provider> Handler<P> for Request<Configure> {
    type Error = Error;
    type Provider = P;
    type Response = ConfigureReply;

    async fn handle(
        self, verifier: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Response<Self::Response>>, Self::Error> {
        handle(verifier, provider, self.body).await
    }
}

impl Body for Configure {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }
}

impl Storable for Configure {
    fn document(&self) -> impl crate::store::Document {
        Document::Configure(self.clone())
    }

    fn indexes(&self) -> HashMap<String, String> {
        let mut indexes = self.build_indexes();
        indexes.extend(self.indexes.clone());
        indexes
    }

    fn add_index(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.indexes.insert(key.into(), value.into());
    }
}

impl TryFrom<Document> for Configure {
    type Error = Error;

    fn try_from(document: Document) -> Result<Self> {
        match document {
            Document::Configure(configure) => Ok(configure),
            _ => Err(bad!("expected `ProtocolsConfigure` message")),
        }
    }
}

impl Configure {
    /// Build flattened indexes for the write message.
    #[cfg(feature = "server")]
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
        let grant = verify_grant::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.author()?, &self.descriptor.base, store).await?;

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

        protocols::validate_structure(&self.descriptor.definition)?;

        Ok(())
    }
}

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
    let (documents, _) = store.query(owner, &builder.build()).await?;
    if documents.is_empty() {
        return Ok(None);
    }

    // unpack messages
    let mut configs = vec![];
    for doc in documents {
        configs.push(Configure::try_from(doc)?);
    }

    Ok(Some(configs))
}

// Fetches the protocol definition for the the protocol specified in the message.
pub async fn definition(
    owner: &str, protocol_uri: &str, store: &impl MessageStore,
) -> Result<Definition> {
    let protocol_uri = utils::uri::clean(protocol_uri)?;

    // use default definition if first-class protocol
    if protocol_uri == PROTOCOL_URI {
        return Ok(DEFINITION.clone());
    }

    let Some(protocols) = fetch_config(owner, Some(protocol_uri), store).await? else {
        return Err(forbidden!("unable to find protocol definition"));
    };
    if protocols.is_empty() {
        return Err(forbidden!("unable to find protocol definition"));
    }

    Ok(protocols[0].descriptor.definition.clone())
}

pub fn rule_set(protocol_path: &str, structure: &BTreeMap<String, RuleSet>) -> Option<RuleSet> {
    let Some((type_name, protocol_path)) = protocol_path.split_once('/') else {
        return structure.get(protocol_path).cloned();
    };
    rule_set(protocol_path, &structure.get(type_name)?.structure)
}
