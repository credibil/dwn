//! # Messages Subscribe
//!
//! Decentralized Web Node messaging framework.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::{StreamExt, future};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::event::{SubscribeFilter, Subscriber};
use crate::messages::MessagesFilter;
use crate::provider::{EventStream, MessageStore, Provider, Signer};
use crate::{Descriptor, Interface, Method, Result, forbidden, permissions, schema};

/// Handle a subscribe message.
///
/// # Errors
/// TODO: Add errors
pub async fn handle(
    owner: &str, subscribe: Subscribe, provider: &impl Provider,
) -> Result<Reply<SubscribeReply>> {
    // authorize the subscriber
    subscribe.authorize(owner, provider).await?;

    // get event stream from provider
    // N.B. the provider is expected to map events to our Event type
    let mut subscriber = EventStream::subscribe(provider, owner).await?;

    // filter the stream before returning
    if !subscribe.descriptor.filters.is_empty() {
        let filter = SubscribeFilter::Messages(subscribe.descriptor.filters);
        let filtered = subscriber.inner.filter(move |event| future::ready(filter.is_match(event)));
        subscriber.inner = Box::pin(filtered);
    }
    
    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(SubscribeReply {
            subscription: subscriber,
        }),
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
    type Reply = SubscribeReply;

    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

impl Subscribe {
    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let author = authzn.author()?;

        if author == owner {
            return Ok(());
        }

        // verify grant
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Err(forbidden!("missing permission grant"));
        };
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, self.descriptor(), store).await?;

        // ensure subscribe filters include scoped protocol
        if grant.data.scope.protocol().is_none() {
            return Ok(());
        };

        let protocol = grant.data.scope.protocol();
        for filter in &self.descriptor.filters {
            if filter.protocol.as_deref() != protocol {
                return Err(forbidden!("filter protocol does not match scoped protocol"));
            }
        }

        Ok(())
    }
}

/// Subscribe reply
#[derive( Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    #[serde(skip)]
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
    pub filters: Vec<MessagesFilter>,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct SubscribeBuilder {
    message_timestamp: DateTime<Utc>,
    filters: Option<Vec<MessagesFilter>>,
    permission_grant_id: Option<String>,
}

/// Builder for creating a permission grant.
impl SubscribeBuilder {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specify event filter to use when subscribing.
    #[must_use]
    pub fn add_filter(mut self, filter: MessagesFilter) -> Self {
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
