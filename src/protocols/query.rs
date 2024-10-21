//! # Messages
//!
//! Decentralized Web Node messaging framework.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Authorization;
use crate::protocols::Configure;
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::service::{Context, Message};
use crate::{Cursor, Descriptor, Interface, Method, Status};

/// Process query message.
pub async fn handle(ctx: &Context, query: Query, provider: impl Provider) -> Result<Reply> {
    //
    query.authorization.authenticate(&provider).await?;
    query.authorize(ctx).await?;

    let entries = fetch_config(&ctx.tenant, query, &provider).await?;

    // TODO: pagination & sorting
    // TODO: return errors in Reply

    Ok(Reply {
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
    tenant: &str, query: Query, provider: &impl Provider,
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
    let (messages, _cursor) = MessageStore::query(provider, tenant, vec![qf], None, None).await?;
    let Message::ProtocolsConfigure(cfg) = messages[0].clone() else {
        return Err(anyhow!("Unexpected message type"));
    };

    Ok(vec![cfg])
}

/// Protocols Query payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

impl Query {
    /// Check message has sufficient privileges.
    pub async fn authorize(&self, ctx: &Context) -> Result<()> {
        let author = self.authorization.author()?;

        // if tenant is author, proceed without further checks
        if author == ctx.tenant {
            return Ok(());
        }

        // if set, query and grant protocols need to match
        if let Some(protocol) = &ctx.grant.scope.protocol {
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
pub struct Reply {
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
