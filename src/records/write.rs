//! # Write
//!
//! `Write` is a message type used to create a new record in the web node.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::io::Read;

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::{EncryptionAlgorithm, Jws, JwsBuilder, PublicKeyJwk};
use vercre_infosec::{Cipher, Signer};

use crate::auth::{self, Authorization, JwsPayload};
use crate::data::cid;
use crate::endpoint::{Context, Message, MessageRecord, MessageType, Reply, Status};
use crate::event::Event;
use crate::protocols::{PROTOCOL_URI, REVOCATION_PATH};
use crate::provider::{BlockStore, EventLog, EventStream, Keyring, MessageStore, Provider};
use crate::records::{protocol, DataStream};
use crate::{
    permissions, unexpected, utils, Descriptor, Error, Interface, Method, Result, MAX_ENCODED_SIZE,
};

/// Handle `RecordsWrite` messages.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(owner: &str, write: Write, provider: &impl Provider) -> Result<Reply> {
    write.authorize(owner, provider).await?;

    // verify integrity of messages with protocol
    if write.descriptor.protocol.is_some() {
        protocol::verify_integrity(owner, &write, provider).await?;
    }

    let existing = existing_entries(owner, &write.record_id, provider).await?;
    let (initial, latest) = first_and_last(&existing).await?;

    // if current message is not the initial write, check 'immutable' properties
    // haven't been altered
    if let Some(initial) = &initial {
        if !write.compare_immutable(initial) {
            return Err(unexpected!("immutable properties do not match"));
        }
    }

    // confirm current message is the latest AND not a delete
    if let Some(latest) = &latest {
        let current_ts = write.descriptor.base.message_timestamp.unwrap_or_default();
        let latest_ts = latest.descriptor.base.message_timestamp.unwrap_or_default();

        if current_ts.cmp(&latest_ts) == Ordering::Less {
            return Err(Error::Conflict("newer write record already exists".to_string()));
        }
        if latest.descriptor.base.method == Method::Delete {
            return Err(unexpected!("RecordsWrite not allowed after RecordsDelete"));
        }
    }

    let (write, code) = if let Some(mut data) = write.data_stream.clone() {
        let write = process_stream(owner, &write, &mut data, provider).await?;
        (write, StatusCode::ACCEPTED)
    } else {
        // if the incoming message is not the initial write, and no `data_stream` is
        // set, we can process
        let (write, code) = if initial.is_some() {
            let Some(latest) = &latest else {
                return Err(unexpected!("newest existing message not found"));
            };
            let write = process_data(owner, &write, latest, provider).await?;
            (write, StatusCode::ACCEPTED)
        } else {
            (write, StatusCode::NO_CONTENT)
        };

        (write, code)
    };

    // ----------------------------------------------------------------
    // TODO: Latest Base State
    // ----------------------------------------------------------------
    // `latest_base` is used to prevent querying of initial writes that do
    // not have data. This prevents a malicious user from gaining access to
    // data by referencing the `data_cid` of private data in their initial
    // writes.
    //
    // `latest_base` is set when the incoming `Write` message is:
    //   - an intial write with data
    //   - not an initial write

    // TODO: the use of `latest` is confusing: refactor to use a `latest_base` flag
    let mut message = MessageRecord::from(&write);
    message.indexes.insert("latestBase".to_string(), Value::Bool(latest.is_none()));

    // save the message and log the event
    MessageStore::put(provider, owner, &message).await?;

    let event = Event {
        message_cid: write.cid()?,
        base: write.descriptor.base.clone(),
        protocol: write.descriptor.protocol.clone(),
    };
    EventLog::append(provider, owner, &event).await?;

    // only emit an event when the message is the latest base state
    if latest.is_none() {
        EventStream::emit(provider, owner, &event).await?;
    }

    // delete messages with the same `record_id` EXCEPT the initial write
    let mut deletable = VecDeque::from(existing);
    let _ = deletable.pop_front(); // initial write is first entry
    for msg in deletable {
        let cid = cid::from_value(&msg)?;
        MessageStore::delete(provider, owner, &cid).await?;
        EventLog::delete(provider, owner, &cid).await?;
    }

    // when message is a grant revocation, delete all grant-authorized
    // messages with timestamp after revocation
    if write.descriptor.protocol == Some(PROTOCOL_URI.to_owned())
        && write.descriptor.protocol_path == Some(REVOCATION_PATH.to_owned())
    {
        revoke_grants(owner, &write, provider).await?;
    }

    // ----------------------------------------------------------------
    // Response Codes
    // ----------------------------------------------------------------
    // In order to discern between a message accepted as a queryable write and
    // something accepted as an initial state we use separate response codes:
    //   - 202 for queryable writes
    //   - 204 for non-queryable writes
    //
    // See https://github.com/TBD54566975/dwn-sdk-js/issues/695 for more details.

    Ok(Reply {
        status: Status {
            code: code.as_u16(),
            detail: Some("OK".to_string()),
        },
        reply: None,
    })
}

/// Records write message payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Write {
    /// Write descriptor.
    pub descriptor: WriteDescriptor,

    /// The message authorization.
    pub authorization: Authorization,

    /// Record CID
    pub record_id: String,

    /// Record context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Record attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Record encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionProperty>,

    /// The base64url encoded data of the record if the data associated with
    /// the recordnis equal or smaller than `MAX_ENCODING_SIZE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,

    /// The data stream of the record if the data associated with the record
    #[serde(skip)]
    pub data_stream: Option<DataStream>,
}

#[async_trait]
impl Message for Write {
    fn cid(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Cid {
            #[serde(flatten)]
            descriptor: WriteDescriptor,
            authorization: Authorization,
        }
        cid::from_value(&Cid {
            descriptor: self.descriptor.clone(),
            authorization: self.authorization.clone(),
        })
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor.base
    }

    fn authorization(&self) -> Option<&Authorization> {
        Some(&self.authorization)
    }

    async fn handle(self, ctx: &Context, provider: &impl Provider) -> Result<Reply> {
        handle(&ctx.owner, self, provider).await
    }
}

impl From<&Write> for MessageRecord {
    fn from(write: &Write) -> Self {
        let mut record = Self {
            message: MessageType::RecordsWrite(write.clone()),
            indexes: Map::new(),
        };
        record.indexes.insert(
            "author".to_string(),
            Value::String(write.authorization.author().unwrap_or_default()),
        );
        record.indexes.insert(
            "dateUpdated".to_string(),
            Value::String(write.descriptor.base.message_timestamp.unwrap_or_default().to_rfc3339()),
        );
        if let Some(tags) = &write.descriptor.tags {
            let mut tag_map = Map::new();
            for (k, v) in tags {
                tag_map.insert(format!("tag.{k}"), v.clone());
            }
            record.indexes.insert("tags".to_string(), Value::Object(tag_map));
        }

        // TODO: add fields
        // attester: None,

        record
    }
}

impl TryFrom<MessageRecord> for Write {
    type Error = crate::Error;

    fn try_from(record: MessageRecord) -> Result<Self> {
        match record.message {
            MessageType::RecordsWrite(write) => Ok(write),
            MessageType::ProtocolsConfigure(_) => {
                Err(unexpected!("expected `RecordsWrite` message"))
            }
        }
    }
}

impl TryFrom<&MessageRecord> for Write {
    type Error = crate::Error;

    fn try_from(record: &MessageRecord) -> Result<Self> {
        match &record.message {
            MessageType::RecordsWrite(write) => Ok(write.clone()),
            MessageType::ProtocolsConfigure(_) => {
                Err(unexpected!("expected `RecordsWrite` message"))
            }
        }
    }
}

impl Write {
    /// Add a data stream to the write message.
    pub fn with_stream(&mut self, data_stream: DataStream) {
        self.data_stream = Some(data_stream);
    }

    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let record_owner = authzn.owner()?;

        // if owner signature is set, it must be the same as the tenant DID
        if record_owner.as_ref().is_some_and(|ro| ro != owner) {
            return Err(unexpected!("record owner is not web node owner"));
        };

        let author = authzn.author()?;

        // authorize author delegate
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let signer = authzn.signer()?;
            let grant = delegated_grant.to_grant()?;
            grant.permit_records_write(&author, &signer, self, store).await?;
        }

        // authorize owner delegate
        if let Some(delegated_grant) = &authzn.owner_delegated_grant {
            let Some(owner) = &record_owner else {
                return Err(unexpected!("owner is required to authorize owner delegate"));
            };
            let signer = authzn.owner_signer()?;
            let grant = delegated_grant.to_grant()?;
            grant.permit_records_write(owner, &signer, self, store).await?;
        }

        // when record owner is set, we can directly grant access
        // (we established `record_owner`== web node owner above)
        if record_owner.is_some() {
            return Ok(());
        };

        // when author is the owner, we can directly grant access
        if author == owner {
            return Ok(());
        }

        // permission grant
        let decoded = Base64UrlUnpadded::decode_vec(&authzn.signature.payload)?;
        let payload: WriteSignaturePayload = serde_json::from_slice(&decoded)?;

        if let Some(permission_grant_id) = &payload.base.permission_grant_id {
            let grant = permissions::fetch_grant(owner, permission_grant_id, store).await?;
            return grant.permit_records_write(owner, &author, self, store).await;
        };

        // protocol-specific authorization
        if self.descriptor.protocol.is_some() {
            return protocol::permit_write(owner, self, store).await;
        }

        Err(unexpected!("message failed authorization"))
    }

    /// Signs the Write message body. The signer is either the author or a delegate.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn sign(
        &mut self, permission_grant_id: Option<String>, protocol_role: Option<String>,
        signer: &impl Signer,
    ) -> Result<()> {
        let (author_did, delegated_grant_id) =
            if let Some(grant) = &self.authorization.author_delegated_grant {
                (
                    Some(auth::signer_did(&grant.authorization.signature)?),
                    Some(cid::from_value(&grant)?),
                )
            } else {
                // TODO: add helper method to Signer trait
                (signer.verification_method().split('#').next().map(ToString::to_string), None)
            };

        // compute `record_id` if not given at construction time
        if self.record_id.is_empty() {
            self.record_id =
                entry_id(self.descriptor.clone(), author_did.clone().unwrap_or_default())?;
        }

        // compute `context_id` if this is a protocol-space record
        if self.descriptor.protocol.is_some() {
            self.context_id = if let Some(parent_id) = &self.descriptor.parent_id {
                Some(format!("{parent_id}/{}", self.record_id))
            } else {
                Some(self.record_id.clone())
            };
        }

        // attestation
        let payload = Payload {
            descriptor_cid: cid::from_value(&self.descriptor)?,
        };
        let signature = JwsBuilder::new().payload(payload).build(signer).await?;
        self.attestation = Some(signature);
        let attestation_cid = Some(cid::from_value(&self.attestation)?);

        let encryption_cid = if let Some(encryption) = &self.encryption {
            Some(cid::from_value(encryption)?)
        } else {
            None
        };

        let payload = WriteSignaturePayload {
            base: JwsPayload {
                descriptor_cid: cid::from_value(&self.descriptor)?,
                permission_grant_id,
                delegated_grant_id,
                protocol_role,
            },
            record_id: self.record_id.clone(),
            context_id: self.context_id.clone(),
            attestation_cid,
            encryption_cid,
        };

        self.authorization.signature = JwsBuilder::new().payload(payload).build(signer).await?;

        Ok(())
    }

    /// Signs the `RecordsWrite` as the web node owner.
    ///
    /// This is used when the web node owner wants to retain a copy of a message that
    /// the owner did not author.
    /// N.B.: requires the `RecordsWrite` to already have the author's signature.
    ///
    /// # Errors
    /// TODO: add errors
    pub async fn sign_as_owner(&mut self, signer: &impl Signer) -> Result<()> {
        if self.authorization.author().is_err() {
            return Err(unexpected!("message signature is required in order to sign as owner"));
        }

        let payload = JwsPayload {
            descriptor_cid: cid::from_value(&self.descriptor)?,
            ..JwsPayload::default()
        };
        let owner_jws = JwsBuilder::new().payload(payload).build(signer).await?;
        self.authorization.owner_signature = Some(owner_jws);

        Ok(())
    }

    /// Signs the `Write` record as a delegate of the web node owner. This is
    /// used when a web node owner-delegate wants to retain a copy of a
    /// message that the owner did not author.
    ///
    /// N.B. requires `Write` to have previously beeen signed by the author.
    ///
    /// # Errors
    /// TODO: add errors
    pub async fn sign_as_delegate(
        &mut self, delegated_grant: DelegatedGrant, signer: &impl Signer,
    ) -> Result<()> {
        if self.authorization.author().is_err() {
            return Err(unexpected!("signature is required in order to sign as owner delegate"));
        }

        //  descriptorCid, delegatedGrantId, permissionGrantId, protocolRole

        let delegated_grant_id = cid::from_value(&delegated_grant)?;
        let descriptor_cid = cid::from_value(&self.descriptor)?;

        let payload = JwsPayload {
            descriptor_cid,
            delegated_grant_id: Some(delegated_grant_id),
            ..JwsPayload::default()
        };
        let owner_jws = JwsBuilder::new().payload(payload).build(signer).await?;

        self.authorization.owner_signature = Some(owner_jws);
        self.authorization.owner_delegated_grant = Some(delegated_grant);

        Ok(())
    }

    /// Encrypt message
    async fn encrypt(
        &self, input: &EncryptionInput, _encryptor: &impl Cipher,
    ) -> Result<EncryptionProperty> {
        // encrypt the data encryption key once per encryption input

        for key in &input.keys {
            if key.derivation_scheme == Some(DerivationScheme::ProtocolPath)
                && self.descriptor.protocol.is_none()
            {
                return Err(unexpected!(
                    "`protocol` must be specified to use `protocols` encryption scheme"
                ));
            }
            if key.derivation_scheme == Some(DerivationScheme::Schemas)
                && self.descriptor.schema.is_none()
            {
                return Err(unexpected!(
                    "`schema` must be specified to use `schema` encryption scheme"
                ));
            }

            // NOTE: right now only `ECIES-ES256K` algorithm is supported for asymmetric encryption,
            // so we will assume that's the algorithm without additional switch/if statements

            // let pk_bytes = Secp256k1.publicJwkToBytes(key.public_key);
            // let output = await Encryption.eciesSecp256k1Encrypt(pk_bytes, input.key);

            //   let encryptedKey = Encoder.bytesToBase64Url(output.ciphertext);
            //   let ephemeralPublicKey = await Secp256k1.publicKeyToJwk(output.ephemeralPublicKey);
            //   let keyEncryptionInitializationVector = Encoder.bytesToBase64Url(output.initializationVector);
            //   let messageAuthenticationCode = Encoder.bytesToBase64Url(output.messageAuthenticationCode);
            //   let encryptedKeyData= EncryptedKey {
            //     rootKeyId            : key.publicKeyId,
            //     algorithm            : key.algorithm ?? EncryptionAlgorithm.EciesSecp256k1,
            //     derivationScheme     : key.derivationScheme,
            //     ephemeralPublicKey,
            //     initializationVector : keyEncryptionInitializationVector,
            //     messageAuthenticationCode,
            //     encryptedKey
            //   };

            //   // we need to attach the actual public key if derivation scheme is protocol-context,
            //   // so that the responder to this message is able to encrypt the message/symmetric key using the same protocol-context derived public key,
            //   // without needing the knowledge of the corresponding private key
            //   if (key.derivationScheme === KeyDerivationScheme.ProtocolContext) {
            //     encryptedKeyData.derivedPublicKey = key.publicKey;
            //   }

            //   keyEncryption.push(encryptedKeyData);
        }

        // const encryption: EncryptionProperty = {
        //   algorithm            : input.algorithm ?? EncryptionAlgorithm.Aes256Ctr,
        //   initializationVector : Encoder.bytesToBase64Url(input.initializationVector),
        //   keyEncryption
        // };

        // return encryption;

        todo!()
    }

    pub(crate) fn is_initial(&self) -> Result<bool> {
        let entry_id = entry_id(self.descriptor.clone(), self.authorization.author()?)?;
        Ok(entry_id == self.record_id)
    }

    // Verify immutable properties of two records are identical.
    fn compare_immutable(&self, other: &Self) -> bool {
        let self_desc = &self.descriptor;
        let other_desc = &other.descriptor;

        if self_desc.base.interface != other_desc.base.interface
            || self_desc.base.method != other_desc.base.method
            || self_desc.protocol != other_desc.protocol
            || self_desc.protocol_path != other_desc.protocol_path
            || self_desc.recipient != other_desc.recipient
            || self_desc.schema != other_desc.schema
            || self_desc.parent_id != other_desc.parent_id
            || self_desc.date_created != other_desc.date_created
        {
            return false;
        }

        true
    }
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteSignaturePayload {
    /// The standard signature payload.
    #[serde(flatten)]
    pub base: JwsPayload,

    /// The ID of the record being signed.
    pub record_id: String,

    /// The context ID of the record being signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Attestation CID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_cid: Option<String>,

    /// Encryption CID .
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_cid: Option<String>,
}

/// Delegated Grant is a special case of `records::Write` used in
/// `Authorization` and `Attestation` grant references
/// (`author_delegated_grant` and `owner_delegated_grant`).
///
/// It is structured to cope with recursive references to `Authorization`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedGrant {
    /// The grant's descriptor.
    pub descriptor: WriteDescriptor,

    ///The grant's authorization.
    pub authorization: Box<Authorization>,

    /// CID referencing the record associated with the message.
    pub record_id: String,

    /// Context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Encoded grant data.
    pub encoded_data: String,
}

impl DelegatedGrant {
    /// Convert [`DelegatedGrant`] to `permissions::Grant`.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn to_grant(&self) -> Result<permissions::Grant> {
        self.clone().try_into()
    }
}

impl TryFrom<DelegatedGrant> for permissions::Grant {
    type Error = crate::Error;

    fn try_from(value: DelegatedGrant) -> Result<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(&value.encoded_data)?;
        let mut grant: Self = serde_json::from_slice(&bytes)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        grant.id.clone_from(&value.record_id);
        grant.grantor = value.authorization.signer()?;
        grant.grantee = value.descriptor.recipient.clone().unwrap_or_default();
        grant.date_granted.clone_from(&value.descriptor.date_created);

        Ok(grant)
    }
}

/// Write descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Record's protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// The protocol path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,

    /// The record's recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// The record's schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Tags associated with the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Map<String, Value>>,

    /// The CID of the record's parent (if exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// CID of the record's data.
    pub data_cid: String,

    /// The record's size in bytes.
    pub data_size: usize,

    /// The record's MIME type. For example, `application/json`.
    pub data_format: String,

    /// The datatime the record was created.
    pub date_created: DateTime<Utc>,

    /// Indicates whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// The datetime of publishing, if published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<DateTime<Utc>>,
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct WriteBuilder {
    recipient: Option<String>,
    protocol: Option<WriteProtocol>,
    protocol_role: Option<String>,
    schema: Option<String>,
    tags: Option<Map<String, Value>>,
    record_id: Option<String>,
    parent_context_id: Option<String>,
    data: WriteData,
    date_created: Option<DateTime<Utc>>,
    message_timestamp: Option<DateTime<Utc>>,
    published: Option<bool>,
    date_published: Option<DateTime<Utc>>,
    data_format: String,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,

    // Encryption settings
    encryption_input: Option<EncryptionInput>,
    // attestation_signers: Option<Vec<Signer>>,
}

/// Protocol.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteProtocol {
    /// Record protocol.
    pub protocol: String,

    /// Protocol path.
    pub protocol_path: String,
}

/// Record data can be raw bytes or CID.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum WriteData {
    /// Data bytes.
    Bytes {
        /// Used to compute `data_cid` when `data_cid` is not set.
        /// Must be the encrypted data bytes if `encryption_input` is set.
        data: Vec<u8>,
    },

    /// Data is provided as a `DataStream` implementing `std::io::Read`.
    Reader {
        /// A data reader for the record's data.
        reader: DataStream,
    },

    /// Data CID.
    Cid {
        /// CID of data already stored by the web node. If not set, the `data`
        /// parameter must be set.
        data_cid: String,

        /// Size of the `data` attribute in bytes. Must be set when `data_cid` is set,
        /// otherwise should be left unset.
        data_size: usize,
    },
}

impl Default for WriteData {
    fn default() -> Self {
        Self::Bytes { data: Vec::new() }
    }
}

/// Encryption settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionInput {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// Symmetric key used to encrypt the data.
    pub key: Vec<u8>,

    /// Array of input that specifies how the symmetric key is encrypted. Each
    /// entry in the array will result in a unique ciphertext of the symmetric
    /// key.
    pub keys: Vec<EncryptionKeyInput>,
}

/// Encryption key settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionKeyInput {
    /// Encryption key derivation scheme.
    pub derivation_scheme: Option<DerivationScheme>,

    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the public key used to encrypt the symmetric key.
    pub public_key_id: String,

    /// The recipient's public key.
    pub public_key: PublicKeyJwk,

    /// The encryption algorithm.
    pub algorithm: EncryptionAlgorithm,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    descriptor_cid: String,
}

impl WriteBuilder {
    /// Returns a new [`WriteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        // set defaults
        Self {
            date_created: Some(now),
            message_timestamp: Some(now),
            data_format: "application/json".to_string(),
            ..Self::default()
        }
    }

    /// Specify the write record's recipient .
    #[must_use]
    pub fn recipient(mut self, recipient: impl Into<String>) -> Self {
        self.recipient = Some(recipient.into());
        self
    }

    /// Set a protocol for the record.
    #[must_use]
    pub fn protocol(mut self, protocol: WriteProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Specify a protocol role for the record.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// Specify a schema to use with the record.
    #[must_use]
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Add a tag to the record.
    #[must_use]
    pub fn add_tag(mut self, name: String, value: Value) -> Self {
        self.tags.get_or_insert_with(Map::new).insert(name, value);
        self
    }

    /// Specify an ID to use for the permission request.
    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    /// Required for a child (non-root) protocol record.
    #[must_use]
    pub fn parent_context_id(mut self, parent_context_id: impl Into<String>) -> Self {
        self.parent_context_id = Some(parent_context_id.into());
        self
    }

    /// Record data as a CID or raw bytes.
    #[must_use]
    pub fn data(mut self, data: WriteData) -> Self {
        self.data = data;
        self
    }

    /// The datetime the record was created. Defaults to now.
    #[must_use]
    pub const fn date_created(mut self, date_created: DateTime<Utc>) -> Self {
        self.date_created = Some(date_created);
        self
    }

    /// The datetime the record was created. Defaults to now.
    #[must_use]
    pub const fn message_timestamp(mut self, message_timestamp: DateTime<Utc>) -> Self {
        self.message_timestamp = Some(message_timestamp);
        self
    }

    /// Whether the record is published.
    #[must_use]
    pub const fn published(mut self, published: bool) -> Self {
        self.published = Some(published);
        self
    }

    /// The datetime the record was published. Defaults to now.
    #[must_use]
    pub const fn date_published(mut self, date_published: DateTime<Utc>) -> Self {
        self.date_published = Some(date_published);
        self
    }

    /// The record's MIME type. Defaults to `application/json`.
    #[must_use]
    pub fn data_format(mut self, data_format: impl Into<String>) -> Self {
        self.data_format = data_format.into();
        self
    }

    /// The delegated grant used with this record.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Specifies whether the record should be encrypted.
    #[must_use]
    pub fn encryption_input(mut self, encryption_input: EncryptionInput) -> Self {
        self.encryption_input = Some(encryption_input);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Build the write message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, keyring: &impl Keyring) -> Result<Write> {
        let now = Utc::now();
        let timestamp = self.message_timestamp.unwrap_or(now);

        let mut write = Write {
            descriptor: WriteDescriptor {
                base: Descriptor {
                    interface: Interface::Records,
                    method: Method::Write,
                    message_timestamp: Some(timestamp),
                },
                recipient: self.recipient,
                tags: self.tags,
                date_created: self.date_created.unwrap_or(now),
                published: self.published,
                data_format: self.data_format,
                parent_id: self.parent_context_id.clone(),
                ..WriteDescriptor::default()
            },
            ..Write::default()
        };

        match self.data {
            WriteData::Bytes { data } => {
                // TODO: store data as encoded_data or in DataStore
                write.descriptor.data_cid = cid::from_value(&data)?;
                write.descriptor.data_size = data.len();
            }
            WriteData::Reader { reader } => {
                let mut stream = reader.clone();
                let (data_cid, data_size) = stream.compute_cid()?;
                write.descriptor.data_cid = data_cid;
                write.descriptor.data_size = data_size;

                write.data_stream = Some(reader);
            }
            WriteData::Cid { data_cid, data_size } => {
                write.descriptor.data_cid = data_cid;
                write.descriptor.data_size = data_size;
            }
        };

        // protocol, protocol_ path
        if let Some(p) = self.protocol {
            let normalized = utils::clean_url(&p.protocol)?;
            write.descriptor.protocol = Some(normalized);
            write.descriptor.protocol_path = Some(p.protocol_path);
        }

        // schema
        if let Some(s) = self.schema {
            write.descriptor.schema = Some(utils::clean_url(&s)?);
        }

        // parent_id - first segment of  `parent_context_id`
        if let Some(id) = self.parent_context_id {
            let parent_id = id.split('/').find(|s| !s.is_empty()).map(ToString::to_string);
            write.descriptor.parent_id = parent_id;
        }

        // when published true and date_published not set
        if self.published.unwrap_or_default() && self.date_published.is_none() {
            write.descriptor.date_published = Some(now);
        }

        write.record_id = self.record_id.unwrap_or_default();
        write.authorization = Authorization {
            author_delegated_grant: self.delegated_grant,
            ..Authorization::default()
        };

        // TODO: encryption
        if let Some(ecryption_input) = &self.encryption_input {
            write.encrypt(ecryption_input, keyring).await?;
        }

        // sign message
        write.sign(self.permission_grant_id, self.protocol_role, keyring).await?;

        Ok(write)
    }
}

/// Encryption output.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProperty {
    algorithm: EncryptionAlgorithm,
    initialization_vector: String,
    key_encryption: Vec<EncryptedKey>,
}

/// Encrypted key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id)
    /// of the root public key used to encrypt the symmetric encryption key.
    root_key_id: String,

    /// The actual derived public key.
    derived_public_key: PublicKeyJwk,
    derivation_scheme: DerivationScheme,
    algorithm: EncryptionAlgorithm,
    initialization_vector: String,
    ephemeral_public_key: PublicKeyJwk,
    message_authentication_code: String,
    encrypted_key: String,
}

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DerivationScheme {
    /// Key derivation using the `dataFormat` value for Flat-space records.
    #[default]
    DataFormats,

    /// Key derivation using protocol context.
    ProtocolContext,

    /// Key derivation using the protocol path.
    ProtocolPath,

    /// Key derivation using the `schema` value for Flat-space records.
    Schemas,
}

// Fetch previous entries for this record, ordered from earliest to latest.
pub(crate) async fn existing_entries(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Vec<Write>> {
    // N.B. only use `interface` to get `RecordsWrite` and `RecordsDelete` messages
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND recordId = '{record_id}'
        ORDER BY descriptor.messageTimestamp ASC
        ",
        interface = Interface::Records,
    );
    let (messages, _) = store.query(owner, &sql).await.unwrap();

    let mut writes = Vec::new();
    for message in messages {
        writes.push(Write::try_from(message)?);
    }

    Ok(writes)
}

// Computes the deterministic Entry ID of the message.
pub(crate) fn entry_id(descriptor: WriteDescriptor, author: String) -> Result<String> {
    #[derive(Serialize)]
    struct EntryId {
        #[serde(flatten)]
        descriptor: WriteDescriptor,
        author: String,
    }
    cid::from_value(&EntryId { descriptor, author })
}

// Fetches the first and last `records::Write` messages associated for the
// `record_id`.
pub(crate) async fn first_and_last(messages: &[Write]) -> Result<(Option<Write>, Option<Write>)> {
    // get initial entry
    let initial = if let Some(first) = messages.first() {
        // check initial write is found
        if !first.is_initial()? {
            return Err(unexpected!("initial write is not earliest message"));
        }
        Some(first)
    } else {
        None
    };

    Ok((initial.cloned(), messages.last().cloned()))
}

async fn process_stream(
    owner: &str, write: &Write, data: &mut DataStream, store: &impl BlockStore,
) -> Result<Write> {
    let mut write = write.clone();

    // when data is below the threshold, store it within MessageStore
    if write.descriptor.data_size <= MAX_ENCODED_SIZE {
        // read data from stream
        let mut data_bytes = Vec::new();
        data.read_to_end(&mut data_bytes)?;

        let data_cid = cid::from_value(&data_bytes)?;
        if write.descriptor.data_cid != data_cid {
            return Err(unexpected!("computed data CID does not match descriptor cid"));
        }
        if write.descriptor.data_size != data_bytes.len() {
            return Err(unexpected!("actual data size does not match descriptor `data_size`"));
        }
        if write.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
            protocol::verify_schema(&write, &data_bytes)?;
        }

        write.descriptor.data_cid = data_cid;
        write.descriptor.data_size = data_bytes.len();
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&data_bytes));
    } else {
        let (data_cid, data_size) = data.to_store(owner, store).await?;

        // verify data CID and size
        if write.descriptor.data_cid != data_cid {
            return Err(unexpected!("computed data CID does not match descriptor cid"));
        }
        if write.descriptor.data_size != data_size {
            return Err(unexpected!("stored data size does not match descriptor data_size"));
        }

        write.descriptor.data_cid = data_cid;
        write.descriptor.data_size = data_size;
    }

    Ok(write)
}

// Write message is not an 'initial write' with no data_stream.
// Check integrity against the most recent existing write.
async fn process_data(
    owner: &str, write: &Write, existing: &Write, store: &impl BlockStore,
) -> Result<Write> {
    // Perform `data_cid` check in case a user attempts to gain access to data
    // by referencing a different known `data_cid`. This  ensures the data is
    // already associated with the latest existing message.
    // See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info
    if existing.descriptor.data_cid != write.descriptor.data_cid {
        return Err(unexpected!("data CID does not match data_cid in descriptor"));
    }
    if existing.descriptor.data_size != write.descriptor.data_size {
        return Err(unexpected!("data size does not match data_size in descriptor"));
    }

    // encode the data from the original write if it is smaller than the
    // data-store threshold
    let mut message = write.clone();
    if write.descriptor.data_size <= MAX_ENCODED_SIZE {
        let Some(encoded) = &existing.encoded_data else {
            return Err(unexpected!("no `encoded_data` in most recent existing message"));
        };
        message.encoded_data = Some(encoded.clone());
    };

    // otherwise, make sure the data is in the data store
    let result = store.get(owner, &write.descriptor.data_cid).await?;
    if result.is_none() {
        return Err(unexpected!(
            "`data_stream` not set and unable to get data from previous message"
        ));
    };

    Ok(message)
}

// Revoke grants if records::Write is a permission revocation .
async fn revoke_grants(owner: &str, write: &Write, provider: &impl Provider) -> Result<()> {
    // get grant from revocation message `parent_id`
    let Some(grant_id) = &write.descriptor.parent_id else {
        return Err(unexpected!("missing `parent_id`"));
    };
    let message_timestamp = write.descriptor.base.message_timestamp.unwrap_or_default();

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{grant_id}'
        AND dateCreated >= '{message_timestamp}
        AND latestBase = true
        ",
        interface = Interface::Records,
        method = Method::Write,
    );

    let (messages, _) = MessageStore::query(provider, owner, &sql).await?;

    // delete any messages with the same `record_id` except the initial write
    for m in messages {
        EventLog::delete(provider, owner, &m.cid()?).await?;
    }

    Ok(())
}
