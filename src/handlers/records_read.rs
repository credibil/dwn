//! # Records Read
//!
//! The records read endpoint handles `RecordsRead` messages — requests to
//! read a persisted [`Write`] message.

use std::io::Cursor;

use anyhow::Context;
use base64ct::{Base64UrlUnpadded, Encoding};
use http::StatusCode;

use crate::Method;
use crate::authorization::Authorization;
use crate::error::{bad_request, forbidden};
use crate::handlers::{
    Body, Error, Handler, Reply, Request, Result, records_write, verify_grant, verify_protocol,
};
use crate::interfaces::Descriptor;
use crate::interfaces::records::{Read, ReadReply, ReadReplyEntry, RecordsFilter, Write};
use crate::provider::{DataStore, MessageStore, Provider};
use crate::store::{self, RecordsQueryBuilder};

/// Handle — or process — a [`Read`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to retrieve the specified message from the
/// [`MessageStore`].
pub async fn handle(owner: &str, provider: &impl Provider, read: Read) -> Result<Reply<ReadReply>> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let query = store::Query::from(read.clone());

    let (entries, _) = MessageStore::query(provider, owner, &query).await?;
    if entries.is_empty() {
        return Err(Error::NotFound("no matching record".to_string()));
    }
    if entries.len() > 1 {
        return Err(bad_request!("multiple messages exist"));
    }

    // if record is deleted, return as NotFound
    if entries[0].descriptor().method == Method::Delete {
        let Some(delete) = entries[0].as_delete() else {
            return Err(bad_request!("expected `RecordsDelete` message"));
        };

        let Ok(Some(write)) =
            records_write::initial_write(owner, &delete.descriptor.record_id, provider).await
        else {
            return Err(bad_request!("initial write for deleted record not found"));
        };

        read.authorize(owner, &write, provider).await?;

        // TODO: return optional body for NotFound error
        // return Err(Error::NotFound("record is deleted".to_string()));

        return Ok(Reply {
            status: StatusCode::NOT_FOUND,
            headers: None,
            body: ReadReply {
                entry: ReadReplyEntry {
                    records_delete: Some(delete.clone()),
                    initial_write: Some(write),
                    records_write: None,
                    data: None,
                },
            },
        });
    }

    let mut write = Write::try_from(&entries[0])?;

    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &write, provider).await?;

    let data = if let Some(encoded) = write.encoded_data {
        write.encoded_data = None;
        let buffer = Base64UrlUnpadded::decode_vec(&encoded).context("decoding data")?;
        Some(Cursor::new(buffer))
    } else {
        use std::io::Read;

        let Some(mut read) =
            DataStore::get(provider, owner, &write.record_id, &write.descriptor.data_cid).await?
        else {
            return Err(Error::NotFound("data not found".to_string()));
        };

        let mut buf = Vec::new();
        read.read_to_end(&mut buf).context("reading data")?;
        Some(Cursor::new(buf))
    };

    write.encoded_data = None;

    // attach initial write if latest RecordsWrite is not initial write
    let initial_write = if write.is_initial()? {
        None
    } else {
        let query = RecordsQueryBuilder::new()
            .add_filter(RecordsFilter::new().record_id(&write.record_id))
            .include_archived(true)
            .build();
        let (entries, _) = MessageStore::query(provider, owner, &query).await?;
        if entries.is_empty() {
            return Err(bad_request!("initial write not found"));
        }

        let Some(mut initial_write) = entries[0].as_write().cloned() else {
            return Err(bad_request!("expected `RecordsWrite` message"));
        };

        initial_write.encoded_data = None;
        Some(initial_write)
    };

    Ok(Reply {
        status: StatusCode::OK,
        headers: None,
        body: ReadReply {
            entry: ReadReplyEntry {
                records_write: Some(write.clone()),
                records_delete: None,
                initial_write,
                data,
            },
        },
    })
}

impl<P: Provider> Handler<P> for Request<Read> {
    type Error = Error;
    type Provider = P;
    type Reply = ReadReply;

    async fn handle(
        self, verifier: &str, provider: &Self::Provider,
    ) -> Result<impl Into<Reply<Self::Reply>>, Self::Error> {
        handle(verifier, provider, self.body).await
    }
}

impl Body for Read {
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }
}

impl Read {
    async fn authorize(&self, owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
        // authorization not required for published data
        if write.descriptor.published.unwrap_or_default() {
            return Ok(());
        }

        let Some(authzn) = &self.authorization else {
            return Err(forbidden!("read not authorized"));
        };
        let author = authzn.author()?;

        // owner can read records on their DWN
        if author == owner {
            return Ok(());
        }

        // recipient can read records they received
        if let Some(recipient) = &write.descriptor.recipient {
            if &author == recipient {
                return Ok(());
            }
        }
        // author can read records they authored
        if author == write.authorization.author()? {
            return Ok(());
        }

        // authorize delegate
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant = delegated_grant.to_grant()?;
            grant.verify_scope(write)?;
        }

        // verify grant
        if let Some(grant_id) = &authzn.payload()?.permission_grant_id {
            let grant = verify_grant::fetch_grant(owner, grant_id, store).await?;
            grant.permit_read(owner, &author, self, write, store).await?;
            return Ok(());
        }

        // verify protocol role and action
        if let Some(protocol) = &write.descriptor.protocol {
            let protocol = verify_protocol::Authorizer::new(protocol)
                .context_id(write.context_id.as_ref())
                .initial_write(write);
            protocol.permit_read(owner, self, store).await?;
            return Ok(());
        }

        Err(forbidden!("read cannot be authorized"))
    }
}
