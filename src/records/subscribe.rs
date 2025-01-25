//! # Subscribe
//!
//! `Subscribe` is a message type used to subscribe a record in the web node.

use futures::{StreamExt, future};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::event::{SubscribeFilter, Subscriber};
use crate::permissions::{Grant, Protocol};
use crate::provider::{EventStream, Provider};
use crate::records::{RecordsFilter, Write};
use crate::{Descriptor, OneOrMany, Result, forbidden};

/// Process `Subscribe` message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, subscribe: Subscribe, provider: &impl Provider,
) -> Result<Reply<SubscribeReply>> {
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
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(SubscribeReply {
            subscription: subscriber,
        }),
    })
}

/// Records Subscribe payload
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscribe {
    /// The Subscribe descriptor.
    pub descriptor: SubscribeDescriptor,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
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
        self.authorization.as_ref()
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

/// Subscribe reply.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeReply {
    /// The subscription to the requested events.
    /// N.B. serialization/deserialization is skipped because the subscriber
    /// `Stream` is not serializable.
    #[serde(skip)]
    pub subscription: Subscriber,
}

/// Subscribe reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeReplyEntry {
    /// The `RecordsWrite` message of the record if record exists.
    #[serde(flatten)]
    pub write: Write,

    /// The initial write of the record if the returned `RecordsWrite` message
    /// itself is not the initial write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_write: Option<Write>,
}

impl Subscribe {
    async fn authorize(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        // only authorize subscriptions to private records
        if self.descriptor.filter.published.unwrap_or_default() {
            return Ok(());
        };

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
            let protocol =
                Protocol::new(protocol).context_id(self.descriptor.filter.context_id.as_ref());
            return protocol.permit_subscribe(owner, self, provider).await;
        }

        // when filter.protocol_role is set, set method to be RecordsWrite or RecordsDelete
        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("missing authorization"));
        };
        if authzn.payload()?.protocol_role.is_some() {
            // FIXME: fix this
            // filter.method = OneOrMany::Many(vec![Method::Write, Method::Delete]);
        }

        Ok(())
    }
}

/// Subscribe descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Filter Records for subscribe.
    pub filter: RecordsFilter,
}
