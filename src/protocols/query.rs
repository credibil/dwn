//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use crate::protocols::Configure;
use crate::provider::Provider;
use crate::service::Authorization;
use crate::{Cursor, Descriptor, Status};

/// Handle a query message.
pub async fn handle(
    tenant: &str, query: Query, provider: impl Provider,
) -> anyhow::Result<QueryReply> {
    //
    // authenticate(message.authorization, didResolver)?;
    // protocolsQuery.authorize(tenant, messageStore).await?;

    let entries = fetch_config(tenant, query).await?;

    Ok(QueryReply {
        status: Status {
            code: 200,
            detail: Some("OK".to_string()),
        },
        entries: Some(entries),
        cursor: None,
    })
}

async fn fetch_config(tenant: &str, query: Query) -> anyhow::Result<Vec<Configure>> {
    // // fetch all published `protocols::Configure` matching the query
    // const filter = {
    //   ...protocolsQuery.message.descriptor.filter,
    //   interface : Interface::Protocols,
    //   method    : Method::Configure,
    //   published : true
    // };
    // const { messages: publishedProtocolsConfigure } = await this.messageStore.query(tenant, [ filter ]);

    // return publishedProtocolsConfigure as ProtocolsConfigureMessage[];

    todo!()
}

/// Protocols Query payload
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Query {
    /// The Query descriptor.
    pub descriptor: QueryDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
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
