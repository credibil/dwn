//! # Messages Read

use std::str::FromStr;

use ::cid::Cid;
use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{Authorization, AuthorizationBuilder};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::permissions::{self, Scope};
use crate::protocols::PROTOCOL_URI;
use crate::provider::{MessageStore, Provider, Signer};
use crate::records::DataStream;
use crate::store::{Entry, EntryType};
use crate::{forbidden, schema, unexpected, Descriptor, Error, Interface, Method, Result};

/// Handle a read message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    owner: &str, read: Read, provider: &impl Provider,
) -> Result<Reply<ReadReply>> {
    let Some(entry) = MessageStore::get(provider, owner, &read.descriptor.message_cid).await?
    else {
        return Err(Error::NotFound("message not found".to_string()));
    };

    // verify the fetched message can be safely returned to the requestor
    read.authorize(owner, &entry, provider).await?;

    let mut message = (*entry).clone();

    // include data with RecordsWrite messages
    let data = if let EntryType::Write(ref mut write) = message {
        //     // return embedded `encoded_data` as entry data stream.
        if let Some(encoded) = write.encoded_data.clone() {
            write.encoded_data = None;
            let bytes = Base64UrlUnpadded::decode_vec(&encoded)?;
            Some(DataStream::from(bytes))
        } else {
            DataStream::from_store(owner, &write.descriptor.data_cid, provider).await?
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

/// `Read` payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Read {
    /// The `Read` descriptor.
    pub descriptor: ReadDescriptor,

    /// The message authorization.
    pub authorization: Authorization,
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
        Some(&self.authorization)
    }

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        handle(owner, self, provider).await
    }
}

impl Read {
    async fn authorize(&self, owner: &str, entry: &Entry, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;

        // owner can read messages they authored
        let author = authzn.author()?;
        if author == owner {
            return Ok(());
        }

        // verify grant
        let Some(grant_id) = &authzn.jws_payload()?.permission_grant_id else {
            return Ok(());
        };
        let grant = permissions::fetch_grant(owner, grant_id, store).await?;
        grant.verify(owner, &author, self.descriptor(), store).await?;
        verify_scope(owner, self, entry, grant.data.scope, store).await?;

        Ok(())
    }
}

// Verify message scope against grant scope.
async fn verify_scope(
    owner: &str, read: &Read, requested: &Entry, scope: Scope, store: &impl MessageStore,
) -> Result<()> {
    // ensure read filters include scoped protocol
    let Some(scope_protocol) = scope.protocol() else {
        // TODO: check this is OK?
        return Ok(());
        //return Err(forbidden!("missing protocol scope",));
    };

    if requested.descriptor().interface == Interface::Protocols {
        let Some(configure) = requested.as_configure() else {
            return Err(forbidden!("message failed scope authorization"));
        };
        if &configure.descriptor.definition.protocol == scope_protocol {
            return Ok(());
        }
    }

    if requested.descriptor().interface == Interface::Records {
        let write = match &requested.message {
            EntryType::Write(write) => write,
            EntryType::Delete(_) => {
                // await RecordsWrite.fetchNewestRecordsWrite(messageStore, tenant, recordsMessage.descriptor.recordId);
                todo!()
            }
            EntryType::Configure(_) => {
                return Err(forbidden!("message failed scope authorization"))
            }
        };

        // protocols match
        if write.descriptor.protocol == Some(scope_protocol.to_string()) {
            return Ok(());
        }

        // we check if the protocol is the internal PermissionsProtocol for further validation
        if write.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
            let permission_scope = permissions::protocol::fetch_scope(owner, write, store).await?;
            let Some(protocol) = permission_scope.protocol() else {
                return Err(forbidden!("missing protocol scope",));
            };
            if protocol == scope_protocol {
                return Ok(());
            }
        }
    }

    Err(forbidden!("message failed scope authorization"))
}

/// `Read` reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ReadReply {
    /// The `Read` descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<ReadReplyEntry>,
}

/// `Read` reply entry
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct ReadReplyEntry {
    /// The CID of the message.
    pub message_cid: String,

    /// The message.
    pub message: EntryType,

    /// The data associated with the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DataStream>,
}

/// Read descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// The CID of the message to read.
    pub message_cid: String,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ReadBuilder {
    message_timestamp: Option<DateTime<Utc>>,
    permission_grant_id: Option<String>,
    message_cid: Option<String>,
}

/// Builder for creating a permission grant.
impl ReadBuilder {
    /// Returns a new [`ReadBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            message_timestamp: Some(Utc::now()),
            ..Self::default()
        }
    }

    /// Specify a permission grant ID to use with the configuration.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify the CID of the message to read.
    #[must_use]
    pub fn message_cid(mut self, message_cid: impl Into<String>) -> Self {
        self.message_cid = Some(message_cid.into());
        self
    }

    /// Generate the Read message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Read> {
        // verify CID
        let Some(message_cid) = self.message_cid else {
            return Err(unexpected!("missing message CID"));
        };
        let _ = Cid::from_str(&message_cid).map_err(|e| unexpected!("invalid CID: {e}"))?;

        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Messages,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            message_cid,
        };

        // authorization
        let mut builder = AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            builder = builder.permission_grant_id(id);
        }
        let authorization = builder.build(signer).await?;

        let read = Read {
            descriptor,
            authorization,
        };

        schema::validate(&read)?;

        Ok(read)
    }
}
