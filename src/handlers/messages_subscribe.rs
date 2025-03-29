//! # Messages Subscribe
//!
//! The messages subscribe endpoint handles `MessagesSubscribe` messages —
//! requests to subscribe to message events matching the provided filter(s).

use futures::{StreamExt, future};
use http::StatusCode;

use crate::endpoint::{Reply, ReplyBody, Status};
use crate::event::SubscribeFilter;
use crate::handlers::verify_grant;
use crate::interfaces::messages::{Subscribe, SubscribeReply};
use crate::provider::{EventStream, MessageStore, Provider};
use crate::{Result, forbidden};

/// Handle — or process — a [`Subscribe`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs creating the subscription [`Subscriber`].
pub async fn handle(
    owner: &str, subscribe: Subscribe, provider: &impl Provider,
) -> Result<Reply> {
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
            code: StatusCode::OK,
            detail: None,
        },
        body: Some(ReplyBody::MessagesSubscribe(SubscribeReply {
            subscription: subscriber,
        })),
    })
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
        let grant = verify_grant::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &authzn.signer()?, &self.descriptor.base, store).await?;

        // ensure subscribe filters include scoped protocol
        if grant.data.scope.protocol().is_none() {
            return Ok(());
        }

        let protocol = grant.data.scope.protocol();
        for filter in &self.descriptor.filters {
            if filter.protocol.as_deref() != protocol {
                return Err(forbidden!("filter and grant protocols do not match"));
            }
        }

        Ok(())
    }
}
