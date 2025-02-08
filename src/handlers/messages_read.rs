//! # Messages Read
//!
//! The messages read endpoint handles `MessagesRead` messages — requests to
//! read a persisted message.
//!
//! Typically, a read request is made to read a message following a successful
//! messages query.

use std::io::Cursor;
use std::str::FromStr;

use ::cid::Cid;
use base64ct::{Base64UrlUnpadded, Encoding};
use http::StatusCode;

use crate::authorization::Authorization;
use crate::endpoint::{Message, Reply, Status};
use crate::grants::Scope;
use crate::handlers::{records_write, verify_grant};
use crate::interfaces::messages::{Read, ReadReply, ReadReplyEntry};
use crate::interfaces::protocols::PROTOCOL_URI;
use crate::interfaces::{Descriptor, Document};
use crate::provider::{DataStore, MessageStore, Provider};
use crate::store::Entry;
use crate::{Error, Interface, Result, forbidden, unexpected};

/// Handle — or process — a [`Read`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to retrieve the specified message from the
/// [`MessageStore`].
pub async fn handle(owner: &str, read: Read, provider: &impl Provider) -> Result<Reply<ReadReply>> {
    // validate message CID
    let cid =
        Cid::from_str(&read.descriptor.message_cid).map_err(|e| unexpected!("invalid CID: {e}"))?;

    let Some(entry) = MessageStore::get(provider, owner, &cid.to_string()).await? else {
        return Err(Error::NotFound("message not found".to_string()));
    };

    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &entry, provider).await?;

    let mut message = entry.message;

    // include data with RecordsWrite messages
    let data = if let Document::Write(ref mut write) = message {
        if let Some(encoded) = write.encoded_data.clone() {
            write.encoded_data = None;
            let bytes = Base64UrlUnpadded::decode_vec(&encoded)?;
            Some(Cursor::new(bytes))
        } else {
            use std::io::Read;
            if let Some(mut read) =
                DataStore::get(provider, owner, &write.record_id, &write.descriptor.data_cid)
                    .await?
            {
                let mut buf = Vec::new();
                read.read_to_end(&mut buf)?;
                Some(Cursor::new(buf))
            } else {
                None
            }
        }
    } else {
        None
    };

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(ReadReply {
            entry: Some(ReadReplyEntry {
                message_cid: read.descriptor.message_cid,
                message,
                data,
            }),
        }),
    })
}

impl Message for Read {
    type Reply = ReadReply;

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

impl Read {
    async fn authorize(&self, owner: &str, entry: &Entry, provider: &impl Provider) -> Result<()> {
        let authzn = &self.authorization;

        // owner can read messages they authored
        let author = authzn.author()?;
        if author == owner {
            return Ok(());
        }

        // verify grant
        let Some(grant_id) = &authzn.payload()?.permission_grant_id else {
            return Err(forbidden!("missing grant ID"));
        };
        let grant = verify_grant::fetch_grant(owner, grant_id, provider).await?;
        grant.verify(owner, &author, self.descriptor(), provider).await?;
        verify_scope(owner, entry, grant.data.scope, provider).await?;

        Ok(())
    }
}

// Verify message scope against grant scope.
async fn verify_scope(
    owner: &str, requested: &Entry, scope: Scope, store: &impl MessageStore,
) -> Result<()> {
    // ensure read filters include scoped protocol
    let Some(protocol) = scope.protocol() else {
        return Ok(());
    };

    if requested.descriptor().interface == Interface::Protocols {
        let Some(configure) = requested.as_configure() else {
            return Err(forbidden!("message failed scope authorization"));
        };
        if configure.descriptor.definition.protocol == protocol {
            return Ok(());
        }
    }

    if requested.descriptor().interface == Interface::Records {
        let write = match &requested.message {
            Document::Write(write) => write.clone(),
            Document::Delete(delete) => {
                let entry =
                    records_write::initial_write(owner, &delete.descriptor.record_id, store)
                        .await?;
                let Some(write) = entry else {
                    return Err(forbidden!("message failed scope authorization"));
                };
                write.clone()
            }
            Document::Configure(_) => {
                return Err(forbidden!("message failed scope authorization"));
            }
        };

        // protocols match
        if write.descriptor.protocol.as_deref() == Some(protocol) {
            return Ok(());
        }

        // check if the protocol is the internal permissions protocol
        if write.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
            let permission_scope = verify_grant::fetch_scope(owner, &write, store).await?;
            if permission_scope.protocol() == Some(protocol) {
                return Ok(());
            }
        }
    }

    Err(forbidden!("message failed scope authorization"))
}
