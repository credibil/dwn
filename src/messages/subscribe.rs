//! # Messages Subscribe
//!
//! Decentralized Web Node messaging framework.

use futures::{StreamExt, future};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::utils::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::event::{SubscribeFilter, Subscriber};
use crate::messages::MessagesFilter;
use crate::provider::{EventStream, MessageStore, Provider};
use crate::{Descriptor, Result, forbidden, permissions};

/// Handle a subscribe message.
///
/// # Errors
/// LATER: Add errors
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
        let Some(grant_id) = &authzn.payload()?.permission_grant_id else {
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
                return Err(forbidden!("filter and grant protocols do not match"));
            }
        }

        Ok(())
    }
}

/// Subscribe reply
#[derive(Debug, Deserialize, Serialize)]
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
