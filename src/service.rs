//! # Service
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

use crate::infosec::Jws;
use crate::{messages, records};

/// Decentralized Web Node messaging is transacted via `Message` objects.
/// Messages contain execution parameters, authorization material, authorization
/// signatures, and signing/encryption information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// The message payload.
    #[serde(flatten)]
    pub payload: Payload,

    /// The message authorization.
    pub authorization: Authorization,
}

/// Message payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Payload {
    /// Messages Query payload
    MessagesQuery {
        /// The Query descriptor.
        descriptor: messages::QueryDescriptor,
    },
    /// Messages Read payload
    MessagesRead {
        /// The Read descriptor.
        descriptor: messages::ReadDescriptor,
    },
    /// Messages Subscribe payload
    MessagesSubscribe {
        /// The Subscribe descriptor.
        descriptor: messages::SubscribeDescriptor,
    },
    /// Records Query payload
    RecordsQuery {
        /// The Query descriptor.
        descriptor: records::QueryDescriptor,
    },
    /// Records Read payload
    RecordsRead {
        /// The Read descriptor.
        descriptor: records::ReadDescriptor,
    },
    /// Records Subscribe payload
    RecordsSubscribe {
        /// The Subscribe descriptor.
        descriptor: records::SubscribeDescriptor,
    },
}

impl Default for Payload {
    fn default() -> Self {
        Payload::MessagesQuery {
            descriptor: Default::default(),
        }
    }
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
