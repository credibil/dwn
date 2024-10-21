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

/// Message context for attaching information used during processing.
pub struct Context {
    /// The web node tenant (or owner)
    pub tenant: String,

    /// The permission grant used to authorize the message
    pub grant: PermissionGrant,
}

/// Send a message.
pub async fn send_message(
    tenant: &str, message: Message, provider: impl Provider,
) -> anyhow::Result<Reply> {
    // base authorization

    let mut ctx = Context {
        tenant: tenant.to_string(),
        grant: PermissionGrant::default(),
    };

    // authorize the message
    if let Some(authzn) = &message.authorization() {
        let base64 = &authzn.signature.payload;
        let decoded = Base64UrlUnpadded::decode_vec(base64)
            .map_err(|e| anyhow!("issue decoding header: {e}"))?;
        let payload: SignaturePayload = serde_json::from_slice(&decoded)
            .map_err(|e| anyhow!("issue deserializing header: {e}"))?;

        if let Some(grant_id) = &payload.permission_grant_id {
            let grant = grant::fetch(tenant, grant_id, &provider).await?;
            message.authorize(tenant, &grant, &provider).await?;

            ctx.grant = grant;
        } else {
            return Err(anyhow!("`permission_grant_id` not found in signature payload"));
        }
    };

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
    pub fn cid(&self) -> anyhow::Result<String> {
        cid::compute_cid(self)
    }

    /// Authorize the message.
    pub async fn authorize(
        &self, tenant: &str, grant: &PermissionGrant, provider: &impl Provider,
    ) -> Result<()> {
        let Some(authzn) = self.authorization() else {
            return Err(anyhow!("no authorization found"));
        };

        let author = authzn.author()?;
        let desc = self.descriptor();

        // verify the `grantee` against intended recipient
        if author != grant.grantee {
            return Err(anyhow!("invalid grantee"));
        }

        // verifies `grantor` against actual signer
        if tenant != &grant.grantor {
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
        let Some(timestamp) = &desc.message_timestamp else {
            return Err(anyhow!("missing message timestamp"));
        };
        self.verify_active(tenant, grant, timestamp, provider).await?;

        Ok(())
    }

    /// Verify that the message is within the allowed time frame of the grant, and
    /// the grant has not been revoked.
    async fn verify_active(
        &self, tenant: &str, grant: &PermissionGrant, timestamp: &str, provider: &impl Provider,
    ) -> Result<()> {
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
        let (messages, _) = MessageStore::query(provider, tenant, vec![qf], sort, None).await?;
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
    pub fn descriptor(&self) -> &Descriptor {
        match self {
            Message::MessagesQuery(query) => &query.descriptor.base,
            Message::MessagesRead(read) => &read.descriptor.base,
            Message::MessagesSubscribe(subscribe) => &subscribe.descriptor.base,
            Message::RecordsWrite(write) => &write.descriptor.base,
            Message::RecordsQuery(query) => &query.descriptor.base,
            Message::RecordsRead(read) => &read.descriptor.base,
            Message::RecordsSubscribe(subscribe) => &subscribe.descriptor.base,
            Message::RecordsDelete(delete) => &delete.descriptor.base,
            Message::ProtocolsConfigure(configure) => &configure.descriptor.base,
            Message::ProtocolsQuery(query) => &query.descriptor.base,
        }
    }

    /// Get message signer's DID from the message authorization.
    pub fn authorization(&self) -> Option<&Authorization> {
        match self {
            Message::MessagesQuery(query) => Some(&query.authorization),
            Message::MessagesRead(read) => Some(&read.authorization),
            Message::MessagesSubscribe(subscribe) => Some(&subscribe.authorization),
            Message::RecordsWrite(write) => Some(&write.authorization),
            Message::RecordsQuery(query) => query.authorization.as_ref(),
            Message::RecordsRead(read) => read.authorization.as_ref(),
            Message::RecordsSubscribe(subscribe) => subscribe.authorization.as_ref(),
            Message::RecordsDelete(delete) => Some(&delete.authorization),
            Message::ProtocolsConfigure(configure) => Some(&configure.authorization),
            Message::ProtocolsQuery(query) => Some(&query.authorization),
        }
    }

    /// Get message signer's DID from the message authorization.
    pub fn signer(&self) -> Option<String> {
        let Some(authzn) = self.authorization() else {
            return None;
            // return Err(anyhow!("no authorization found"));
        };

        if let Ok(signer) = auth::signer_did(&authzn.signature) {
            return Some(signer);
        } else {
            return None;
        }
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
