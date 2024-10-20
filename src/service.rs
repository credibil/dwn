//! # Service
//!
//! Decentralized Web Node messaging framework.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::messages::query;
use crate::provider::Provider;
use crate::{auth, cid, messages, protocols, records, Descriptor};

/// Send a message.
pub async fn send_message(
    tenant: &str, message: Message, provider: impl Provider,
) -> anyhow::Result<Reply> {
    match message {
        Message::MessagesQuery(query) => {
            let reply = query::handle(tenant, query, provider).await?;
            Ok(Reply::MessagesQuery(reply))
        }
        Message::ProtocolsQuery(query) => {
            let reply = protocols::query::handle(tenant, query, provider).await?;
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

    /// Base descriptor common to all messages.
    pub fn descriptor(&self) -> anyhow::Result<&Descriptor> {
        Ok(match self {
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
        })
    }

    /// Get message signer's DID from the message authorization.
    pub fn signer(&self) -> Option<String> {
        let authzn = match self {
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
        };

        let Some(authzn) = authzn else {
            return None;
            // return Err(anyhow!("No authorization found"));
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
