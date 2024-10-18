//! # Service
//!
//! Decentralized Web Node messaging framework.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use vercre_infosec::Jws;

use crate::messages::query;
use crate::provider::Provider;
use crate::{cid, messages, protocols, records};

/// Send a message.
pub async fn send_message(message: Message, provider: impl Provider) -> anyhow::Result<Reply> {
    println!("Sending message");

    match message {
        Message::MessagesQuery(query) => {
            let reply = query::handle("tenant", query, provider).await?;
            Ok(Reply::MessagesQuery(reply))
        }
        _ => {
            return Err(anyhow!("Unsupported message"));
        }
    }

    // Ok(())
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

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The signature of the message signer.
    /// N.B.: Not the author of the message when signer is a delegate.
    pub signature: Jws,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// An "overriding" signature for a DWN owner or owner-delegate to store a
    /// message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}

/// Delegated grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedGrant {
    /// the grant's authorization.
    pub authorization: Box<Authorization>,

    /// CID referencing the record associated with the message.
    pub record_id: String,

    /// Context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    //---
    // descriptor: records::WriteDescriptor,
    //---
    encoded_data: String,
}

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The signature of the message signer.
    /// N.B.: Not the author of the message when signer is a delegate.
    pub signature: Jws,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// An "overriding" signature for a DWN owner or owner-delegate to store a
    /// message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}
