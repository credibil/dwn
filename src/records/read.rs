//! # Read
//!
//! `Read` is a message type used to read a record in the web node.

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::permissions::GrantData;
use crate::provider::{MessageStore, Provider, Signer};
use crate::records::{DelegatedGrant, Delete, RecordsFilter, Write};
use crate::service::{Context, Message};
use crate::{cid, Descriptor, Interface, Method};

/// Process `Read` message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    ctx: &Context, read: Read, provider: impl Provider,
) -> Result<ReadReply> {
    // get the latest active messages
    // N.B. only use `interface` to get `RecordsWrite` and `RecordsDelete` messages
    let filter_sql = read.descriptor.filter.to_sql();

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        {filter_sql}
        ORDER BY descriptor.messageTimestamp ASC
        ",
        interface = Interface::Records,
    );

    let (messages, _) = MessageStore::query(&provider, &ctx.owner, &sql).await?;
    if messages.is_empty() {
        // status: { code: 404, detail: 'Not Found' }
        return Ok(ReadReply::default());
    }

    // TODO: filter by author and attester
    // self.descriptor.author = author_did;

    if messages.len() > 1 {
        return Err(anyhow!("multiple messages exist for the RecordsRead filter"));
    }
    let message = &messages[0];

    // if the matched message is a RecordsDelete, mark as not-found and return
    // both the RecordsDelete and the initial RecordsWrite
    if message.descriptor().method == Method::Delete {
        //   let initial_write = await RecordsWrite.fetchInitialRecordsWriteMessage(this.messageStore, tenant, recordsDeleteMessage.descriptor.recordId);
        //   if initial_write.is_none() {
        //     return Err(anyhow!("Initial write for deleted record not found"));
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

    let Message::RecordsWrite(mut write) = message.clone() else {
        return Err(anyhow!("unexpected message type"));
    };

    authorize(&ctx.owner, &read, &write)?;

    let data = if let Some(encoded) = write.encoded_data {
        write.encoded_data = None;
        let bytes = Base64UrlUnpadded::decode_vec(&encoded)?;
        serde_json::from_slice::<GrantData>(&bytes)?
    } else {
        // TODO: implement data retrieval
        GrantData::default()
        //   const result = await this.dataStore.get(tenant, write.recordId, write.descriptor.dataCid);
        //   if (result?.dataStream === undefined) {
        //     return {
        //       status: { code: 404, detail: 'Not Found' }
        //     };
        //   }
        //   data = result.dataStream;
    };

    // attach initial write if latest RecordsWrite is not initial write
    let initial_write = if write.is_initial()? {
        None
    } else {
        let sql = format!(
            "
            WHERE descriptor.interface = '{interface}'
            AND descriptor.method = '{method}'
            AND recordId = '{record_id}'
            ",
            interface = Interface::Records,
            method = Method::Write,
            record_id = write.record_id,
        ); // isLatestBaseState: false

        let (messages, _) = MessageStore::query(&provider, &ctx.owner, &sql).await?;
        if messages.is_empty() {
            return Err(anyhow!("initial write not found"));
        }
        let Message::RecordsWrite(mut initial_write) = messages[0].clone() else {
            return Err(anyhow!("unexpected message type"));
        };
        initial_write.encoded_data = None;
        Some(initial_write)
    };

    Ok(ReadReply {
        records_write: Some(write),
        initial_write,
        ..ReadReply::default()
    })
}

fn authorize(owner: &str, read: &Read, write: &Write) -> Result<()> {
    let Some(authzn) = &read.authorization else {
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

    Err(anyhow!("unauthorized"))
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

/// Read reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadReply {
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
    pub data: Option<GrantData>,
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
                AuthorizationBuilder::new().descriptor_cid(cid::compute(&descriptor)?);
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
