//! # Messages Subscribe
//!
//! Decentralized Web Node messaging framework.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Context, Message, Reply, ReplyType, Status};
use crate::event::{Listener, Subscriber};
use crate::messages::Filter;
use crate::permissions::{self, ScopeType};
use crate::provider::{EventStream, MessageStore, Provider, Signer};
use crate::{schema, Descriptor, Error, Interface, Method, Result};

/// Handle a subscribe message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    owner: &str, subscribe: Subscribe, provider: &impl Provider,
) -> Result<Reply> {
    subscribe.authorize(owner, provider).await?;

    let message_cid = subscribe.cid()?;

    let mut listener = Listener {
        filters: subscribe.descriptor.filters,
        ..Default::default()
    };
    let subscriber = EventStream::subscribe(provider, owner, &message_cid, &mut listener).await?;

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        reply: Some(ReplyType::MessagesSubscribe(SubscribeReply {
            subscription: subscriber,
        })),
    })
}

/// Subscribe message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
}

#[async_trait]
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

    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply> {
        handle(&ctx.owner, self, provider).await
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

/// Subscribe reply
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    pub subscription: Subscriber,
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
    // callback: Option<EventHandler>,
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

    /// Specify event filter to use when subscribing.
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

    // /// Specify a permission grant ID to use with the configuration.
    // #[must_use]
    // pub fn callback(mut self, callback: EventHandler) -> Self {
    //     self.callback = Some(callback);
    //     self
    // }

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

        // let Some(callback) = self.callback else {
        //     return Err(unexpected!("missing callback"));
        // };

        let query = Subscribe {
            descriptor,
            authorization,
            // callback,
        };

        schema::validate(&query)?;

        Ok(query)
    }
}
