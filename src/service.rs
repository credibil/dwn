//! # Service
//!
//! Decentralized Web Node messaging framework.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::auth::Authorization;
use crate::permissions::Grant;
use crate::provider::{MessageStore, Provider};
use crate::{cid, messages, permissions, protocols, records, schema, Descriptor, Status};

/// Process web node messages.
///
/// # Errors
/// TODO: Add errors
pub async fn handle_message(
    owner: &str, message: Message, provider: impl Provider,
) -> anyhow::Result<Reply> {
    // if !tenant_gate.active(owner)? {
    //     return Ok(Reply::GenericReply(GenericReply {
    //         status: Status {
    //             code: 401,
    //             detail: Some("{tenant} is not active".to_string()),
    //         },
    //     }));
    // }

    if let Err(e) = message.validate_schema() {
        return Ok(Reply {
            status: Status {
                code: 400,
                detail: Some(e.to_string()),
            },
            ..Reply::default()
        });
    }

    let mut ctx = Context {
        owner: owner.to_string(),
        ..Context::default()
    };

    // authenticate author, if set
    // N.B. `authorize()` will determine whether `authorization` should be set
    if let Some(authzn) = message.authorization() {
        authzn.authenticate(&provider).await?;
    };

    // authorize
    message.authorize(&mut ctx, &provider).await?;

    // route to appropriate handler
    let (code, response) = match message {
        Message::ProtocolsQuery(query) => (
            200,
            protocols::query::handle(&ctx, query, provider).await.map(ReplyEntry::ProtocolsQuery),
        ),
        Message::ProtocolsConfigure(configure) => (
            202,
            protocols::configure::handle(&ctx, configure, provider)
                .await
                .map(ReplyEntry::ProtocolsConfigure),
        ),
        Message::RecordsWrite(write) => {
            let reply = records::write::handle(&ctx, write, provider).await?;
            let code = reply.code;
            (code, Ok(ReplyEntry::RecordsWrite(reply)))
        }
        Message::RecordsRead(read) => {
            (202, records::read::handle(&ctx, read, provider).await.map(ReplyEntry::RecordsRead))
        }

        _ => (400, Err(anyhow!("Unsupported message"))),
    };

    // map response to reply
    match response {
        Ok(entry) => {
            let detail = match code {
                202 => "Accepted",
                204 => "No Content",
                _ => "OK",
            };

            Ok(Reply {
                status: Status {
                    code,
                    detail: Some(detail.to_string()),
                },
                entry: Some(entry),
            })
        }
        Err(e) => Ok(Reply {
            status: Status {
                code: 400,
                detail: Some(e.to_string()),
            },
            ..Reply::default()
        }),
    }
}

/// Message context for attaching information used during processing.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The web node owner (aka tenant).
    pub owner: String,

    /// The author of the message.
    pub author: String,

    /// The permission grant used to authorize the message
    pub grant: Option<Grant>,
}

/// Decentralized Web Node messaging is transacted via `Message` objects.
/// Messages contain execution parameters, authorization material, authorization
/// signatures, and signing/encryption information.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Message {
    MessagesQuery(messages::Query),
    MessagesRead(messages::Read),
    MessagesSubscribe(messages::Subscribe),
    RecordsWrite(records::Write),
    RecordsQuery(records::Query),
    RecordsRead(records::Read),
    RecordsSubscribe(records::Subscribe),
    RecordsDelete(records::Delete),
    ProtocolsConfigure(protocols::Configure),
    ProtocolsQuery(protocols::Query),
}

impl Message {
    /// Compute the CID of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn cid(&self) -> anyhow::Result<String> {
        cid::compute(self)
    }

    /// Base descriptor common to all messages.
    #[must_use]
    pub const fn descriptor(&self) -> &Descriptor {
        match self {
            Self::MessagesQuery(query) => &query.descriptor.base,
            Self::MessagesRead(read) => &read.descriptor.base,
            Self::MessagesSubscribe(subscribe) => &subscribe.descriptor.base,
            Self::RecordsWrite(write) => &write.descriptor.base,
            Self::RecordsQuery(query) => &query.descriptor.base,
            Self::RecordsRead(read) => &read.descriptor.base,
            Self::RecordsSubscribe(subscribe) => &subscribe.descriptor.base,
            Self::RecordsDelete(delete) => &delete.descriptor.base,
            Self::ProtocolsConfigure(configure) => &configure.descriptor.base,
            Self::ProtocolsQuery(query) => &query.descriptor.base,
        }
    }

    /// Get message signer's DID from the message authorization.
    #[must_use]
    pub const fn authorization(&self) -> Option<&Authorization> {
        match self {
            Self::MessagesQuery(query) => Some(&query.authorization),
            Self::MessagesRead(read) => Some(&read.authorization),
            Self::MessagesSubscribe(subscribe) => Some(&subscribe.authorization),
            Self::RecordsWrite(write) => Some(&write.authorization),
            Self::RecordsQuery(query) => query.authorization.as_ref(),
            Self::RecordsRead(read) => read.authorization.as_ref(),
            Self::RecordsSubscribe(subscribe) => subscribe.authorization.as_ref(),
            Self::RecordsDelete(delete) => Some(&delete.authorization),
            Self::ProtocolsConfigure(configure) => Some(&configure.authorization),
            Self::ProtocolsQuery(query) => Some(&query.authorization),
        }
    }

    /// Authorize the message.
    ///
    /// # Errors
    /// TODO: Add errors
    async fn authorize(&self, ctx: &mut Context, store: &impl MessageStore) -> Result<()> {
        // message has no authorization
        let Some(authzn) = self.authorization() else {
            return Ok(());
        };
        ctx.author = authzn.author()?;

        // no checks needed when message author is web node owner
        if ctx.author == ctx.owner {
            return Ok(());
        }

        let payload = authzn.jws_payload()?;
        let Some(grant_id) = &payload.permission_grant_id else {
            return Err(anyhow!("`permission_grant_id` not found in signature payload"));
        };

        let grant = permissions::fetch_grant(&ctx.owner, grant_id, store).await?;
        grant.verify(&ctx.author, &authzn.signer()?, self.descriptor(), store).await?;

        // save for later use
        ctx.grant = Some(grant);

        Ok(())
    }

    /// Validate a message against the corresponding JSON schema.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn validate_schema(&self) -> Result<()> {
        let descriptor = self.descriptor();
        let key = format!("{}-{}", descriptor.interface, descriptor.method).to_lowercase();
        schema::validate_schema(&key, self)
    }
}

/// Reply to a web node message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Reply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// Reply specific to the endpoint.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<ReplyEntry>,
}

/// Reply entry specific to the endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ReplyEntry {
    /// Reply entry for messages query.
    MessagesQuery(messages::QueryReply),
    // MessagesRead(messages::ReadReply),
    // MessagesSubscribe(messages::SubscribeReply),
    /// Reply entry for records write.
    RecordsWrite(records::WriteReply),
    RecordsRead(records::ReadReply),
    // RecordsQuery(records::QueryReply),
    // RecordsSubscribe(records::SubscribeReply),
    // RecordsDelete(records::DeleteReply),
    /// Reply entry for protocols configure.
    ProtocolsConfigure(protocols::ConfigureReply),

    /// Reply entry for protocols query.
    ProtocolsQuery(protocols::QueryReply),
}

impl Default for ReplyEntry {
    fn default() -> Self {
        Self::MessagesQuery(messages::QueryReply::default())
    }
}
