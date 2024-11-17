//! # Read
//!
//! `Read` is a message type used to read a record in the web node.

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Context, Message, Reply, Status};
use crate::provider::{MessageStore, Provider, Signer};
use crate::records::{DataStream, DelegatedGrant, Delete, RecordsFilter, Write};
use crate::{unexpected, Descriptor, Error, Interface, Method, Result};

/// Process `Read` message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    owner: &str, read: Read, provider: &impl Provider,
) -> Result<Reply<ReadReply>> {
    // get the latest active `RecordsWrite` and `RecordsDelete` messages
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}' 
        {filter_sql}
        AND queryable = true
        ORDER BY descriptor.messageTimestamp DESC
        ",
        interface = Interface::Records,
        filter_sql = read.descriptor.filter.to_sql(),
    );

    let (messages, _) = MessageStore::query(provider, owner, &sql).await?;
    if messages.is_empty() {
        return Err(Error::NotFound("no matching records found".to_string()));
    }
    if messages.len() > 2 {
        return Err(unexpected!("multiple messages exist for the RecordsRead filter"));
    }

    let mut write = Write::try_from(&messages[0])?;

    // if the matched message is a RecordsDelete, mark as not-found and return
    // both the RecordsDelete and the initial RecordsWrite
    if write.descriptor().method == Method::Delete {
        // TODO: implement this

        //   let initial_write = await RecordsWrite.fetchInitialRecordsWriteMessage(this.messageStore, tenant, recordsDeleteMessage.descriptor.recordId);
        //   if initial_write.is_none() {
        //     return Err(unexpected!("Initial write for deleted record not found"));
        //   }

        //   // perform authorization before returning the delete and initial write messages
        //   const parsedInitialWrite = await RecordsWrite.parse(initial_write);
        //
        // if let Err(e)= RecordsReadHandler.authorizeRecordsRead(tenant, recordsRead, parsedInitialWrite, this.messageStore){
        //     // return messageReplyFromError(error, 401);
        //     return Err(e);
        // }
        //
        // return {
        //     status : { code: 404, detail: 'Not Found' },
        //     entry  : {
        //       recordsDelete: recordsDeleteMessage,
        //       initialWrite
        //     }
        // }
    }

    // TODO: review against the original code — it should take a store provider
    read.authorize(owner, &write)?;

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
        let sql = format!(
            "
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'
            AND recordId = '{record_id}'
            AND queryable = false
            ORDER BY descriptor.messageTimestamp ASC
            ",
            interface = Interface::Records,
            method = Method::Write,
            record_id = write.record_id,
        );

        let (messages, _) = MessageStore::query(provider, owner, &sql).await?;
        if messages.is_empty() {
            return Err(unexpected!("initial write not found"));
        }

        let Some(mut initial_write) = messages[0].as_write().cloned() else {
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

#[async_trait]
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

    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(&ctx.owner, self, provider).await
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
    fn authorize(&self, owner: &str, write: &Write) -> Result<()> {
        let Some(authzn) = &self.authorization else {
            return Ok(());
        };
        let author = authzn.author()?;

        // authorize delegate
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let grant = delegated_grant.to_grant()?;
            grant.verify_scope(write)?;
        }
        // if author is owner, directly grant access
        if author == owner {
            return Ok(());
        }
        // authorization not required for published data
        if write.descriptor.published.unwrap_or_default() {
            return Ok(());
        }

        if let Some(recipient) = &write.descriptor.recipient {
            if &author == recipient {
                return Ok(());
            }
        }
        if author == write.authorization.author()? {
            return Ok(());
        }

        Err(unexpected!("unauthorized"))
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
pub struct ReadBuilder {
    filter: RecordsFilter,
    message_timestamp: Option<DateTime<Utc>>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    authorize: Option<bool>,
}

impl ReadBuilder {
    /// Returns a new [`ReadBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        // set defaults
        Self {
            message_timestamp: Some(now),
            ..Self::default()
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn filter(mut self, filter: RecordsFilter) -> Self {
        self.filter = filter;
        self
    }

    /// The datetime the record was created. Defaults to now.
    #[must_use]
    pub const fn message_timestamp(mut self, message_timestamp: DateTime<Utc>) -> Self {
        self.message_timestamp = Some(message_timestamp);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

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

    /// Build the write message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Read> {
        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.normalize()?,
        };

        let authorization = if self.authorize.unwrap_or(true) {
            let mut builder =
                AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
            if let Some(id) = self.permission_grant_id {
                builder = builder.permission_grant_id(id);
            }
            Some(builder.build(signer).await?)
        } else {
            None
        };

        Ok(Read {
            descriptor,
            authorization,
        })
    }
}
