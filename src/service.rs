//! # Service
//!
//! Decentralized Web Node messaging framework.

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, SignaturePayload};
use crate::permissions::Grant;
use crate::provider::Provider;
use crate::records::Write;
use crate::{auth, cid, messages, permissions, protocols, records, schema, Descriptor, Status};

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
        return Ok(Reply::GenericReply(GenericReply {
            status: Status {
                code: 400,
                detail: Some(e.to_string()),
            },
        }));
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
    match message {
        // Message::MessagesQuery(query) => {
        //     let reply = messages::query::handle(&ctx.owner, query, provider).await?;
        //     Ok(Reply::MessagesQuery(reply))
        // }
        Message::ProtocolsQuery(query) => {
            let reply = protocols::query::handle(&ctx, query, provider).await?;
            Ok(Reply::ProtocolsQuery(reply))
        }
        Message::ProtocolsConfigure(configure) => {
            let reply = protocols::configure::handle(&ctx, configure, provider).await?;
            Ok(Reply::ProtocolsConfigure(reply))
        }
        _ => Err(anyhow!("Unsupported message")),
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

    /// Get message author's DID.
    #[must_use]
    pub fn author(&self) -> Option<String> {
        if let Some(author_grant) = &self.authorization()?.author_delegated_grant {
            // HACK: temporary solution to get the signer DID
            return Self::RecordsWrite(Write {
                authorization: (*author_grant.authorization).clone(),
                ..Write::default()
            })
            .signer();
        }

        self.signer()
    }

    /// Get message signer's DID.
    #[must_use]
    pub fn signer(&self) -> Option<String> {
        let authzn = self.authorization()?;
        if let Ok(signer) = auth::signer_did(&authzn.signature) {
            return Some(signer);
        }
        None
    }

    /// Authorize the message.
    ///
    /// # Errors
    /// TODO: Add errors
    async fn authorize(&self, ctx: &mut Context, provider: &impl Provider) -> Result<()> {
        // message has no authorization
        let Some(authzn) = self.authorization() else {
            return Ok(());
        };
        ctx.author = authzn.author()?;

        // no checks needed when message author is web node owner
        if ctx.author == ctx.owner {
            return Ok(());
        }

        let base64 = &authzn.signature.payload;
        let decoded = Base64UrlUnpadded::decode_vec(base64)
            .map_err(|e| anyhow!("issue decoding header: {e}"))?;
        let payload: SignaturePayload = serde_json::from_slice(&decoded)
            .map_err(|e| anyhow!("issue deserializing header: {e}"))?;

        let Some(grant_id) = &payload.permission_grant_id else {
            return Err(anyhow!("`grant_id` not found in signature payload"));
        };

        let grant = permissions::fetch_grant(&ctx.owner, grant_id, provider).await?;
        grant.verify(&ctx.author, &ctx.owner, self.descriptor(), provider).await?;

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
        let key = format!("{}{}", descriptor.interface, descriptor.method);
        schema::validate_schema(&key, self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Reply {
    GenericReply(GenericReply),
    MessagesQuery(messages::QueryReply),
    // MessagesRead(messages::ReadReply),
    // MessagesSubscribe(messages::SubscribeReply),
    // RecordsWrite(records::WriteReply),
    // RecordsQuery(records::QueryReply),
    // RecordsRead(records::ReadReply),
    // RecordsSubscribe(records::SubscribeReply),
    // RecordsDelete(records::DeleteReply),
    ProtocolsConfigure(protocols::ConfigureReply),
    ProtocolsQuery(protocols::QueryReply),
}

/// Generic reply.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenericReply {
    status: Status,
}
