//! # Records Read
//!
//! The records read endpoint handles `RecordsRead` messages — requests to
//! read a persisted [`Write`] message.

use std::io::Cursor;

use base64ct::{Base64UrlUnpadded, Encoding};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::endpoint::{Message, Reply, Status};
use crate::permissions::{self, Protocol};
use crate::provider::{DataStore, MessageStore, Provider};
use crate::records::{Delete, RecordsFilter, Write, write};
use crate::store::{self, RecordsQueryBuilder};
use crate::utils::cid;
use crate::{Descriptor, Error, Method, Result, forbidden, unexpected};

/// Handle — or process — a [`Read`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to retrieve the specified message from the
/// [`MessageStore`].
pub async fn handle(owner: &str, read: Read, provider: &impl Provider) -> Result<Reply<ReadReply>> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let query = store::Query::from(read.clone());

    let (entries, _) = MessageStore::query(provider, owner, &query).await?;
    if entries.is_empty() {
        return Err(Error::NotFound("no matching record".to_string()));
    }
    if entries.len() > 1 {
        return Err(unexpected!("multiple messages exist"));
    }

    // if record is deleted, return as NotFound
    if entries[0].descriptor().method == Method::Delete {
        let Some(delete) = entries[0].as_delete() else {
            return Err(unexpected!("expected `RecordsDelete` message"));
        };

        let Ok(Some(write)) =
            write::initial_write(owner, &delete.descriptor.record_id, provider).await
        else {
            return Err(unexpected!("initial write for deleted record not found"));
        };

        read.authorize(owner, &write, provider).await?;

        // TODO: return optional body for NotFound error
        // return Err(Error::NotFound("record is deleted".to_string()));

        return Ok(Reply {
            status: Status {
                code: StatusCode::NOT_FOUND.as_u16(),
                detail: None,
            },
            body: Some(ReadReply {
                entry: ReadReplyEntry {
                    records_delete: Some(delete.clone()),
                    initial_write: Some(write),
                    records_write: None,
                    data: None,
                },
            }),
        });
    }

    let mut write = Write::try_from(&entries[0])?;

    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &write, provider).await?;

    let data = if let Some(encoded) = write.encoded_data {
        write.encoded_data = None;
        let buffer = Base64UrlUnpadded::decode_vec(&encoded)?;
        Some(Cursor::new(buffer))
    } else {
        use std::io::Read;

        let Some(mut read) =
            DataStore::get(provider, owner, &write.record_id, &write.descriptor.data_cid).await?
        else {
            return Err(Error::NotFound("data not found".to_string()));
        };

        let mut buf = Vec::new();
        read.read_to_end(&mut buf)?;
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
            return Err(unexpected!("initial write not found"));
        }

        let Some(mut initial_write) = entries[0].as_write().cloned() else {
            return Err(unexpected!("expected `RecordsWrite` message"));
        };

        initial_write.encoded_data = None;
        Some(initial_write)
    };

    Ok(Reply {
        status: Status {
            code: StatusCode::OK.as_u16(),
            detail: None,
        },
        body: Some(ReadReply {
            entry: ReadReplyEntry {
                records_write: Some(write.clone()),
                records_delete: None,
                initial_write,
                data,
            },
        }),
    })
}

/// The [`Read`] message expected by the handler.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Read {
    /// Read descriptor.
    pub descriptor: ReadDescriptor,

    /// Message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
}

impl Message for Read {
    type Reply = ReadReply;

    fn cid(&self) -> Result<String> {
        cid::from_value(self)
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

/// [`ReadReply`] is returned by the handler in the [`Reply`] `body` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReply {
    /// The read reply entry.
    pub entry: ReadReplyEntry,
}

/// [`ReadReplyEntry`] represents the [`Write`] entry returned for a successful
/// 'read'.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReplyEntry {
    /// The latest `RecordsWrite` message of the record if record exists
    /// (not deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_write: Option<Write>,

    /// The `RecordsDelete` if the record is deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_delete: Option<Delete>,

    /// The initial write of the record if the returned `RecordsWrite` message
    /// itself is not the initial write or if a `RecordsDelete` is returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_write: Option<Write>,

    /// The data for the record.
    #[serde(skip)]
    pub data: Option<Cursor<Vec<u8>>>,
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
            let grant = permissions::fetch_grant(owner, grant_id, store).await?;
            grant.permit_read(owner, &author, self, write, store).await?;
            return Ok(());
        }

        // verify protocol role and action
        if let Some(protocol_id) = &write.descriptor.protocol {
            // TODO: add `parent_id` to protocol builder
            let protocol = Protocol::new(protocol_id).context_id(write.context_id.as_ref());
            protocol.permit_read(owner, self, write, store).await?;
            return Ok(());
        }

        Err(forbidden!("read cannot be authorized"))
    }
}

/// The [`Read`]  message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Defines the filter for the read.
    pub filter: RecordsFilter,
}
