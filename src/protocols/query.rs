//! # Messages
//!
//! Decentralized Web Node messaging framework.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::permissions::ScopeType;
use crate::protocols::Configure;
use crate::provider::{MessageStore, Provider, Signer};
use crate::service::{Context, Message};
use crate::{
    cid, schema, unexpected, utils, Cursor, Descriptor, Interface, Method, Result, Status,
};
/// Process query message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(owner: &str, query: Query, provider: impl Provider) -> Result<QueryReply> {
    let mut ctx = Context::new(owner);
    Message::validate(&query, &mut ctx, &provider).await?;
    query.authorize(&ctx)?;

    let entries = fetch_config(&ctx.owner, query.descriptor.filter, &provider).await?;

    // TODO: pagination & sorting
    // TODO: return errors in Reply

    Ok(QueryReply {
        status: Status {
            code: 200,
            detail: Some("OK".to_string()),
        },
        entries,
        cursor: None,
    })
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

impl Message for Query {
    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
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

/// Fetch published `protocols::Configure` matching the query
pub(crate) async fn fetch_config(
    owner: &str, filter: Option<Filter>, store: &impl MessageStore,
) -> Result<Option<Vec<Configure>>> {
    let mut protocol = String::new();
    if let Some(filter) = filter {
        let protocol_uri = utils::clean_url(&filter.protocol)?;
        protocol = format!("AND descriptor.definition.protocol = '{protocol_uri}'");
    };

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND descriptor.definition.published = true
        {protocol}
        ",
        interface = Interface::Protocols,
        method = Method::Configure,
    );

    // execute query
    let (messages, _) = store.query::<Configure>(owner, &sql).await?;
    if messages.is_empty() {
        return Ok(None);
    }
    Ok(Some(messages))
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
        let ScopeType::Protocols { protocol } = &grant.data.scope.scope_type else {
            return Err(unexpected!("missing protocol in grant scope"));
        };
        if let Some(protocol) = &protocol {
            let Some(filter) = &self.descriptor.filter else {
                return Err(unexpected!("missing filter"));
            };
            if protocol != &filter.protocol {
                return Err(unexpected!("unauthorized protocol"));
            }
        }

        Ok(())
    }
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
    message_timestamp: Option<DateTime<Utc>>,
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
            message_timestamp: Some(Utc::now()),
            ..Self::default()
        }
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn filter(mut self, protocol: impl Into<String>) -> Self {
        self.filter = Some(Filter {
            protocol: protocol.into(),
        });
        self
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
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
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(signer).await?;

        let query = Query {
            descriptor,
            authorization,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}
