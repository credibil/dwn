//! # Messages
//!
//! Decentralized Web Node messaging framework.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{Authorization, SignaturePayload};
use crate::protocols::Configure;
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::service::Message;
use crate::{Cursor, Descriptor, Interface, Method, Status};

/// Handle a query message.
pub async fn handle(tenant: &str, query: Query, provider: impl Provider) -> Result<Reply> {
    //
    query.authorization.authenticate(&provider).await?;
    // protocolsQuery.authorize(tenant, messageStore).await?;

    let entries = fetch_config(tenant, query, &provider).await?;

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
    /// Verify message signatures.
    pub async fn authorize(&self, tenant: &str, provider: &impl Provider) -> Result<()> {
        let author = self.authorization.author()?;

        // if author is the same as the target tenant, we can directly grant access
        if author == tenant {
            return Ok(());
        }

        let base64 = &self.authorization.signature.payload;
        let decoded = Base64UrlUnpadded::decode_vec(base64)
            .map_err(|e| anyhow!("issue decoding header: {e}"))?;
        let payload: SignaturePayload = serde_json::from_slice(&decoded)
            .map_err(|e| anyhow!("issue deserializing header: {e}"))?;

        if let Some(grant_id)=payload.permission_grant_id{
            // let grant = PermissionsProtocol.fetchGrant(tenant, messageStore, grant_id).await?;
            // ProtocolsGrantAuthorization.authorizeQuery({
            //     expectedGrantor : tenant,
            //     expectedGrantee : author,
            //     incomingMessage : self,
            //     permissionGrant : grant,
            //     messageStore
            // }).await?;
        } else {
            return Err(anyhow!("failed authorization"));
        }



        todo!()
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
