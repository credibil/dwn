//! # Read
//!
//! `Read` is a message type used to read a record in the web node.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::authorization::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::permissions::{self, Protocol};
use crate::provider::{MessageStore, Provider, Signer};
use crate::records::{DataStream, DelegatedGrant, Delete, RecordsFilter, Write, write};
use crate::store::RecordsQuery;
use crate::{Descriptor, Error, Interface, Method, Result, forbidden, unexpected};

/// Process `Read` message.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(owner: &str, read: Read, provider: &impl Provider) -> Result<Reply<ReadReply>> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let mut query = RecordsQuery::from(read.clone());
    query.method = None;

    let entries = MessageStore::query(provider, owner, &query.into()).await?;
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
        let Ok(initial_write) =
            write::initial_write(owner, &delete.descriptor.record_id, provider).await
        else {
            return Err(unexpected!("initial write for deleted record not found"));
        };
        let Some(write) = initial_write else {
            return Err(unexpected!("initial write for deleted record not found"));
        };

        read.authorize(owner, &write, provider).await?;

        // FIXME: return optional body for NotFound error
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

    // FIXME: review against the original code — it should take a store provider
    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &write, provider).await?;

    let data = if let Some(encoded) = write.encoded_data {
        write.encoded_data = None;
        let buffer = Base64UrlUnpadded::decode_vec(&encoded)?;
        Some(DataStream::from(buffer))
    } else {
        DataStream::from_store(owner, &write.descriptor.data_cid, provider).await?
    };

    write.encoded_data = None;

    // attach initial write if latest RecordsWrite is not initial write
    let initial_write = if write.is_initial()? {
        None
    } else {
        let query = RecordsQuery::new()
            .add_filter(RecordsFilter::new().record_id(&write.record_id))
            .include_archived(true);
        let records = MessageStore::query(provider, owner, &query.into()).await?;
        if records.is_empty() {
            return Err(unexpected!("initial write not found"));
        }

        let Some(mut initial_write) = records[0].as_write().cloned() else {
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

/// Records read message payload
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

/// Read reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReply {
    /// The read reply entry.
    pub entry: ReadReplyEntry,
}

/// Read reply.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DataStream>,
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
        if let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id {
            let grant = permissions::fetch_grant(owner, grant_id, store).await?;
            grant.permit_read(owner, &author, self, write, store).await?;
            return Ok(());
        }

        // verify protocol role and action
        if let Some(protocol_id) = &write.descriptor.protocol {
            // FIXME: add `parent_id` to protocol builder
            let protocol = Protocol::new(protocol_id).context_id(write.context_id.as_ref());
            protocol.permit_read(owner, self, write, store).await?;
            return Ok(());
        }

        Err(forbidden!("read cannot be authorized"))
    }
}

/// Reads read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Defines the filter for the read.
    pub filter: RecordsFilter,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ReadBuilder<F, S> {
    message_timestamp: DateTime<Utc>,
    filter: F,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    signer: S,
}

pub struct Unsigned;
pub struct Signed<'a, S: Signer>(pub &'a S);

pub struct Unfiltered;
pub struct Filtered(RecordsFilter);

impl Default for ReadBuilder<Unfiltered, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadBuilder<Unfiltered, Unsigned> {
    /// Returns a new [`ReadBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            filter: Unfiltered,
            permission_grant_id: None,
            protocol_role: None,
            delegated_grant: None,
            signer: Unsigned,
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn filter(self, filter: RecordsFilter) -> ReadBuilder<Filtered, Unsigned> {
        ReadBuilder {
            message_timestamp: self.message_timestamp,
            filter: Filtered(filter),
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            signer: Unsigned,
        }
    }
}

impl<'a, F> ReadBuilder<F, Unsigned> {
    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    // /// Specify a protocol role for the record.
    // #[must_use]
    // pub const fn authorize(mut self, authorize: bool) -> Self {
    //     self.authorize = Some(authorize);
    //     self
    // }

    /// Specify a protocol role for the record.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// The delegated grant used with this record.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signer>(self, signer: &'a S) -> ReadBuilder<F, Signed<'a, S>> {
        ReadBuilder {
            message_timestamp: self.message_timestamp,
            filter: self.filter,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            signer: Signed(signer),
        }
    }
}

impl ReadBuilder<Filtered, Unsigned> {
    /// Build and return an anonymous (unsigned) Read message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn build(self) -> Result<Read> {
        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0,
        };

        Ok(Read {
            descriptor,
            authorization: None,
        })
    }
}

impl<S: Signer> ReadBuilder<Filtered, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self) -> Result<Read> {
        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0.normalize()?,
        };

        let mut auth_builder =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            auth_builder = auth_builder.permission_grant_id(id);
        }
        if let Some(role) = self.protocol_role {
            auth_builder = auth_builder.protocol_role(role);
        }
        if let Some(delegated_grant) = self.delegated_grant {
            auth_builder = auth_builder.delegated_grant(delegated_grant);
        }

        Ok(Read {
            descriptor,
            authorization: Some(auth_builder.build(self.signer.0).await?),
        })
    }
}
