//! # Messages
//!
//! Decentralized Web Node messaging framework.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::protocols::Configure;
use crate::provider::{MessageStore, Provider, Signer};
use crate::query::{self, Compare, Criterion};
use crate::service::{Context, Message};
use crate::{cid, Cursor, Descriptor, Interface, Method, Status};

/// Process query message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    ctx: &Context, query: Query, provider: impl Provider,
) -> Result<QueryReply> {
    query.authorize(ctx)?;
    let entries = fetch_config(&ctx.owner, query, &provider).await?;

    // TODO: pagination & sorting
    // TODO: return errors in Reply

    Ok(QueryReply {
        status: Status {
            code: 200,
            detail: Some("OK".to_string()),
        },
        entries: Some(entries),
        cursor: None,
    })
}

/// Fetch published `protocols::Configure` matching the query
async fn fetch_config(
    owner: &str, query: Query, provider: &impl Provider,
) -> Result<Vec<Configure>> {
    let mut qf = query::Filter {
        criteria: BTreeMap::<String, Criterion>::new(),
    };

    qf.criteria.insert(
        "descriptor.interface".to_string(),
        Criterion::Single(Compare::Equal(Value::String(Interface::Protocols.to_string()))),
    );
    qf.criteria.insert(
        "descriptor.method".to_string(),
        Criterion::Single(Compare::Equal(Value::String(Method::Configure.to_string()))),
    );
    qf.criteria.insert(
        "descriptor.definition.published".to_string(),
        Criterion::Single(Compare::Equal(Value::Bool(true))),
    );

    if let Some(filter) = query.descriptor.filter {
        qf.criteria.insert(
            "descriptor.definition.protocol".to_string(),
            Criterion::Single(Compare::Equal(Value::String(filter.protocol))),
        );
    }

    // execute query
    let (messages, _cursor) = MessageStore::query(provider, owner, vec![qf], None, None).await?;
    let Some(msg) = messages.first() else {
        return Err(anyhow!("no matching message"));
    };
    let Message::ProtocolsConfigure(cfg) = msg else {
        return Err(anyhow!("Unexpected message type"));
    };

    Ok(vec![cfg.clone()])
}

/// Protocols Query payload
///
/// # Errors
/// TODO: Add errors
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

impl Query {
    /// Check message has sufficient privileges.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn authorize(&self, ctx: &Context) -> Result<()> {
        // no grant -> author == owner
        let Some(grant) = &ctx.grant else {
            return Ok(());
        };

        // if set, query and grant protocols need to match
        if let Some(protocol) = &grant.data.scope.protocol {
            let Some(filter) = &self.descriptor.filter else {
                return Err(anyhow!("missing filter"));
            };
            if protocol != &filter.protocol {
                return Err(anyhow!("unauthorized protocol"));
            }
        }

        Ok(())
    }
}

/// Messages Query reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryReply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// The Query descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<Configure>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Query descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct QueryDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for query.
    pub filter: Option<Filter>,
}

/// Protocol filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// Protocol matching the specified protocol.
    pub protocol: String,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct QueryBuilder {
    message_timestamp: Option<String>,
    filter: Option<Filter>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl QueryBuilder {
    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Some(Utc::now().to_rfc3339()),
            ..Self::default()
        }
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn filter(mut self, protocol: String) -> Self {
        self.filter = Some(Filter { protocol });
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
    pub async fn build(self, signer: &impl Signer) -> Result<Query> {
        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Protocols,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::compute(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(signer).await?;

        let query = Query {
            descriptor,
            authorization,
        };

        let message = Message::ProtocolsQuery(query.clone());
        message.validate_schema()?;

        Ok(query)
    }
}
