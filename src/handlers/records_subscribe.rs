//! # Records Subscribe
//!
//! The records subscribe endpoint handles `RecordsSubscribe` messages —
//! requests to subscribe to records events matching the provided filter(s).

use futures::{StreamExt, future};
use http::StatusCode;

use crate::endpoint::{Reply, ReplyBody, Status};
use crate::event::SubscribeFilter;
use crate::grants::Grant;
use crate::handlers::verify_protocol;
use crate::interfaces::records::{Subscribe, SubscribeReply};
use crate::provider::{EventStream, Provider};
use crate::{OneOrMany, Result, forbidden};

/// Handle — or process — a [`Subscribe`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs creating the subscription [`Subscriber`].
pub async fn handle(owner: &str, subscribe: Subscribe, provider: &impl Provider) -> Result<Reply> {
    // authorize subscription
    subscribe.authorize(owner, provider).await?;

    // get event stream from provider
    // N.B. the provider is expected to map events to our Event type
    let mut subscriber = EventStream::subscribe(provider, owner).await?;

    // apply filtering before returning
    let mut filter = subscribe.descriptor.filter.clone();

    let authzn =
        subscribe.authorization.as_ref().ok_or_else(|| forbidden!("missing authorization"))?;
    let author = authzn.author()?;
    if author != owner {
        // non-owners can only see records they created or received
        filter.author = Some(OneOrMany::One(author.clone()));
        filter.recipient = Some(OneOrMany::One(author));
    }

    let filter = SubscribeFilter::Records(filter);
    let filtered = subscriber.inner.filter(move |event| future::ready(filter.is_match(event)));
    subscriber.inner = Box::pin(filtered);

    Ok(Reply {
        status: Status {
            code: StatusCode::OK,
            detail: None,
        },
        body: Some(ReplyBody::RecordsSubscribe(SubscribeReply {
            subscription: subscriber,
        })),
    })
}

impl Subscribe {
    async fn authorize(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        // only need to authorize subscriptions to private records
        if self.descriptor.filter.published.unwrap_or_default() {
            return Ok(());
        }

        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        let author = authzn.author()?;

        // verify grant
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant: Grant = delegated_grant.try_into()?;
            grant.permit_subscribe(&author, &authzn.signer()?, self, provider).await?;
        }

        // verify protocol when request invokes a protocol role
        if let Some(protocol) = &authzn.payload()?.protocol_role {
            let protocol = verify_protocol::Authorizer::new(protocol)
                .context_id(self.descriptor.filter.context_id.as_ref());
            return protocol.permit_subscribe(owner, self, provider).await;
        }

        // when filter.protocol_role is set, set method to be RecordsWrite or RecordsDelete
        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        if authzn.payload()?.protocol_role.is_some() {
            // TODO: determine whether this is required
            // filter.method = OneOrMany::Many(vec![Method::Write, Method::Delete]);
        }

        Ok(())
    }
}
