//! # Messages Subscribe
//!
//! Decentralized Web Node messaging framework.

use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::messages::{Event, Filter, Subscription};
use crate::permissions::{self, ScopeType};
use crate::provider::{EventStream, MessageStore, Provider, Signer};
use crate::service::Context;
use crate::{cid, schema, Descriptor, Error, Interface, Message, Method, Result, Status};

/// Handle a subscribe message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(
    owner: &str, subscribe: Subscribe, sub_handler: impl Fn(Event) -> Result<()> + Send + Sync,
    provider: &impl Provider,
) -> Result<SubscribeReply> {
    let mut ctx = Context::new(owner);
    Message::validate(&subscribe, &mut ctx, provider).await?;
    subscribe.authorize(owner, provider).await?;

    // let mut filter_sql = String::new();
    // for filter in subscribe.descriptor.filters {
    //     if filter_sql.is_empty() {
    //         filter_sql.push_str("WHERE\n");
    //     } else {
    //         filter_sql.push_str("OR\n");
    //     }
    //     filter_sql.push('(');
    //     filter_sql.push_str(&filter.to_sql());
    //     filter_sql.push(')');
    // }

    let listener = |_event_owner: &str, event: Event| -> anyhow::Result<()> {
        // if owner == event_owner && FilterUtility.matchAnyFilter(eventIndexes, messagesFilters) {
        sub_handler(event).map_err(Into::into)
        // }
    };

    let message_cid = subscribe.cid()?;
    let _subscription = EventStream::subscribe(provider, owner, &message_cid, listener).await?;
    // const subscription = await this.eventStream.subscribe(tenant, messageCid, listener);

    Ok(SubscribeReply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        subscription: None, // Some(Subscription {
                            //     id: "123".to_string(),
                            //     close: || Ok(()),
                            // }),
    })
}

/// Messages Subscribe payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

impl Message for Subscribe {
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

impl Subscribe {
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = authzn.author()?;

        if author == owner {
            return Ok(());
        }

        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Ok(());
        };

        // verify grant
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(&author, &authzn.signer()?, self.descriptor(), store).await?;

        // ensure subscribe filters include scoped protocol
        let ScopeType::Protocols { protocol } = &grant.data.scope.scope_type else {
            return Err(Error::Unauthorized("missing protocol scope".to_string()));
        };

        if protocol.is_none() {
            return Ok(());
        }

        for filter in &self.descriptor.filters {
            if &filter.protocol != protocol {
                return Err(Error::Unauthorized(
                    "filter protocol does not match scoped protocol".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Messages Subscribe reply
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SubscribeReply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// The Subscribe descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<Subscription>,
}

/// Subscribe descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filters to apply when subscribing to messages.
    pub filters: Vec<Filter>,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct SubscribeBuilder {
    message_timestamp: Option<DateTime<Utc>>,
    filters: Option<Vec<Filter>>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl SubscribeBuilder {
    /// Returns a new [`SubscribeBuilder`]
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
    pub fn add_filter(mut self, filter: Filter) -> Self {
        self.filters.get_or_insert_with(Vec::new).push(filter);
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
    pub async fn build(self, signer: &impl Signer) -> Result<Subscribe> {
        let descriptor = SubscribeDescriptor {
            base: Descriptor {
                interface: Interface::Messages,
                method: Method::Subscribe,
                message_timestamp: self.message_timestamp,
            },
            filters: self.filters.unwrap_or_default(),
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(signer).await?;

        let query = Subscribe {
            descriptor,
            authorization,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}
