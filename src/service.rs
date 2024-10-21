//! # Service
//!
//! Decentralized Web Node messaging framework.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{grant, Authorization, PermissionGrant, SignaturePayload};
use crate::messages::{Direction, Sort};
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::{auth, cid, messages, protocols, records, Descriptor};

/// Process web node messages.
///
/// # Errors
/// TODO: Add errors
pub async fn message(
    tenant: &str, message: Message, provider: impl Provider,
) -> anyhow::Result<Reply> {
    let mut ctx = Context {
        tenant: tenant.to_string(),
        grant: None,
    };

    // general message authorization
    message.authorize(&mut ctx, &provider).await?;

    match message {
        Message::MessagesQuery(query) => {
            let reply = messages::query::handle(&ctx.tenant, query, provider).await?;
            Ok(Reply::MessagesQuery(reply))
        }
        Message::ProtocolsQuery(query) => {
            let reply = protocols::query::handle(&ctx, query, provider).await?;
            Ok(Reply::ProtocolsQuery(reply))
        }
        _ => Err(anyhow!("Unsupported message")),
    }
}

/// Message context for attaching information used during processing.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The web node tenant (or owner)
    pub tenant: String,

    /// The permission grant used to authorize the message
    pub grant: Option<PermissionGrant>,
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

    /// Authorize the message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn authorize(&self, ctx: &mut Context, provider: &impl Provider) -> Result<()> {
        // message has no authorization
        let Some(authzn) = self.authorization() else {
            return Ok(());
        };

        // when tenant is author, we don't need any further checks
        if ctx.tenant == authzn.author()? {
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
        let grant = grant::fetch(&ctx.tenant, grant_id, provider).await?;

        let author = authzn.author()?;
        let desc = self.descriptor();

        // verify the `grantee` against intended recipient
        if author != grant.grantee {
            return Err(anyhow!("invalid grantee"));
        }

        // verifies `grantor` against actual signer
        if ctx.tenant != grant.grantor {
            return Err(anyhow!("invalid grantor"));
        }

        // verify grant scope for interface
        if desc.interface != grant.scope.interface {
            return Err(anyhow!("message interface not within the scope of grant {}", grant.id));
        }

        // verify grant scope method
        if desc.method != grant.scope.method {
            return Err(anyhow!("message method not within the scope of grant {}", grant.id));
        }

        // verify the message is within the grant's time frame
        self.is_grant_current(ctx, provider).await?;

        // save grant for later use
        ctx.grant = Some(grant);

        Ok(())
    }

    /// Verify the message is 1) within the grant's time frame, and 2) the grant
    /// has not been revoked
    async fn is_grant_current(&self, ctx: &Context, provider: &impl Provider) -> Result<()> {
        let Some(timestamp) = &self.descriptor().message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };

        let Some(grant) = &ctx.grant else {
            return Err(anyhow!("missing grant"));
        };

        // Check that message is within the grant's time frame
        if timestamp < &grant.date_granted {
            return Err(anyhow!("grant is not yet active"));
        }
        if timestamp >= &grant.date_expires {
            return Err(anyhow!("grant has expired"));
        }

        // Check if grant has been revoked
        let mut qf = query::Filter {
            criteria: BTreeMap::<String, Criterion>::new(),
        };
        qf.criteria.insert(
            "parentId".to_string(),
            Criterion::Single(Compare::Equal(Value::String(grant.id.clone()))),
        );
        qf.criteria.insert(
            "protocolPath".to_string(),
            Criterion::Single(Compare::Equal(Value::String("grant/revocation".to_string()))),
        );
        qf.criteria.insert(
            "isLatestBaseState".to_string(),
            Criterion::Single(Compare::Equal(Value::Bool(true))),
        );

        // find oldest message in the revocation chain
        let sort = Some(Sort {
            message_timestamp: Some(Direction::Descending),
            ..Default::default()
        });
        let (messages, _) =
            MessageStore::query(provider, &ctx.tenant, vec![qf], sort, None).await?;
        let Some(oldest) = messages.first().cloned() else {
            return Err(anyhow!("grant has been revoked"));
        };

        let Some(message_timestamp) = &oldest.descriptor().message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };

        if message_timestamp.as_str() <= timestamp {
            return Err(anyhow!("grant with CID {} has been revoked", grant.id));
        }

        Ok(())
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

    /// Get message signer's DID from the message authorization.
    #[must_use]
    pub fn signer(&self) -> Option<String> {
        let Some(authzn) = self.authorization() else {
            return None;
            // return Err(anyhow!("no authorization found"));
        };
        if let Ok(signer) = auth::signer_did(&authzn.signature) {
            return Some(signer);
        }
        
        None
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Reply {
    MessagesQuery(messages::QueryReply),
    // MessagesRead(messages::ReadReply),
    // MessagesSubscribe(messages::SubscribeReply),
    // RecordsWrite(records::WriteReply),
    // RecordsQuery(records::QueryReply),
    // RecordsRead(records::ReadReply),
    // RecordsSubscribe(records::SubscribeReply),
    // RecordsDelete(records::DeleteReply),
    // ProtocolsConfigure(protocols::ConfigureReply),
    ProtocolsQuery(protocols::QueryReply),
}
