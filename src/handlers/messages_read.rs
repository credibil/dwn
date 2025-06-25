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
use anyhow::Context;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_core::api::{Body, Handler, Request, Response};

use crate::Interface;
use crate::authorization::Authorization;
use crate::error::{bad_request, forbidden};
use crate::grants::Scope;
use crate::handlers::{BodyExt, Error, Result, records_write, verify_grant};
use crate::interfaces::messages::{Read, ReadReply, ReadReplyEntry};
use crate::interfaces::protocols::PROTOCOL_URI;
use crate::interfaces::{Descriptor, Document};
use crate::provider::{DataStore, MessageStore, Provider};

/// Handle — or process — a [`Read`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to retrieve the specified message from the
/// [`MessageStore`].
async fn handle(owner: &str, provider: &impl Provider, read: Read) -> Result<ReadReply> {
    // validate message CID
    let cid = Cid::from_str(&read.descriptor.message_cid)
        .map_err(|e| bad_request!("invalid CID: {e}"))?;

    let Some(mut document) = MessageStore::get(provider, owner, &cid.to_string()).await? else {
        return Err(Error::NotFound("message not found".to_string()));
    };

    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &document, provider).await?;

    // include data with RecordsWrite messages
    let data = if let Document::Write(ref mut write) = document {
        if let Some(encoded) = write.encoded_data.clone() {
            write.encoded_data = None;
            let bytes = Base64UrlUnpadded::decode_vec(&encoded).context("decoding data")?;
            Some(Cursor::new(bytes))
        } else {
            use std::io::Read;
            if let Some(mut read) =
                DataStore::get(provider, owner, &write.record_id, &write.descriptor.data_cid)
                    .await?
            {
                let mut buf = Vec::new();
                read.read_to_end(&mut buf).context("reading `write` data")?;
                Some(Cursor::new(buf))
            } else {
                None
            }
        }
    } else {
        None
    };

    Ok(ReadReply {
        entry: Some(ReadReplyEntry {
            message_cid: read.descriptor.message_cid,
            message: document,
            data,
        }),
    })
}

impl<P: Provider> Handler<ReadReply, P> for Request<Read> {
    type Error = Error;

    async fn handle(self, verifier: &str, provider: &P) -> Result<impl Into<Response<ReadReply>>> {
        self.body.validate(provider).await?;
        handle(verifier, provider, self.body).await
    }
}

impl Body for Read {}
impl BodyExt for Read {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }
}

impl Read {
    async fn authorize(
        &self, owner: &str, document: &Document, provider: &impl Provider,
    ) -> Result<()> {
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
        grant.verify(owner, &author, &self.descriptor.base, provider).await?;
        verify_scope(owner, document, grant.data.scope, provider).await?;

        Ok(())
    }
}

// Verify message scope against grant scope.
async fn verify_scope(
    owner: &str, requested: &Document, scope: Scope, store: &impl MessageStore,
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
        let write = match &requested {
            Document::Write(write) => write.clone(),
            Document::Delete(delete) => {
                let result =
                    records_write::initial_write(owner, &delete.descriptor.record_id, store)
                        .await?;
                let Some(write) = result else {
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
