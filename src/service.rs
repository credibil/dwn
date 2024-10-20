//! # Service
//!
//! Decentralized Web Node messaging framework.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::messages::query;
use crate::provider::Provider;
use crate::{cid, messages, protocols, records, Descriptor};

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

    pub fn descriptor(&self) -> anyhow::Result<&Descriptor> {
        match self {
            Message::MessagesQuery(query) => Ok(&query.descriptor.base),
            Message::MessagesRead(read) => Ok(&read.descriptor.base),
            Message::MessagesSubscribe(subscribe) => Ok(&subscribe.descriptor.base),
            Message::RecordsWrite(write) => Ok(&write.descriptor.base),
            Message::RecordsQuery(query) => Ok(&query.descriptor.base),
            Message::RecordsRead(read) => Ok(&read.descriptor.base),
            Message::RecordsSubscribe(subscribe) => Ok(&subscribe.descriptor.base),
            Message::RecordsDelete(delete) => Ok(&delete.descriptor.base),
            Message::ProtocolsConfigure(configure) => Ok(&configure.descriptor.base),
            Message::ProtocolsQuery(query) => Ok(&query.descriptor.base),
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
