//! # Write
//!
//! `Write` is a message type used to create a new record in the web node.

use std::cmp::Ordering;
use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::{EncryptionAlgorithm, Jws, PublicKeyJwk, Type};
use vercre_infosec::{Cipher, Signer};

use crate::auth::{Authorization, JwsPayload};
use crate::protocols::{PROTOCOL_URI, REVOCATION_PATH};
use crate::provider::{DataStore, Event, EventLog, EventStream, Keyring, MessageStore, Provider};
use crate::records::protocol;
use crate::service::{Context, Message};
use crate::{cid, permissions, utils, Descriptor, Interface, Method, MAX_ENCODED_SIZE};

/// Process `Write` message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    ctx: &Context, write: Write, provider: impl Provider,
) -> Result<WriteReply> {
    // verify integrity of messages with protocol
    if write.descriptor.protocol.is_some() {
        protocol::verify_integrity(&ctx.owner, &write, &provider).await?;
    }

    // authorize the message
    authorize(&ctx.owner, &write, &provider).await?;

    let messages = existing_entries(&ctx.owner, &write.record_id, &provider).await?;
    let (initial, latest) = first_and_last(&messages).await?;

    // if current message is not the initial write, check 'immutable' properties
    // haven't been altered
    if let Some(initial) = &initial {
        if !write.compare_immutable(initial) {
            return Err(anyhow!("immutable properties do not match"));
        }
    }

    // confirm current message is the latest AND not a delete
    if let Some(latest) = &latest {
        let current_ts = write.descriptor.base.message_timestamp.unwrap_or_default();
        let latest_ts = latest.descriptor.base.message_timestamp.unwrap_or_default();

        if current_ts.cmp(&latest_ts) == Ordering::Less {
            return Err(anyhow!("newer write record already exists"));
        }
        if latest.descriptor.base.method == Method::Delete {
            return Err(anyhow!("RecordsWrite not allowed after RecordsDelete"));
        }
    }

    // ----------------------------------------------------------------
    // Latest Base State
    // ----------------------------------------------------------------
    // `is_latest` is used to prevent querying of initial writes that do
    // not have data. This prevents a malicious user from gaining access to
    // data by referencing the `data_cid` of private data in their initial
    // writes.
    //
    // `is_latest` is set to true when either the incoming message comes
    //  with data OR is not an initial write.
    //
    // See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info

    // ----------------------------------------------------------------
    // Response Codes
    // ----------------------------------------------------------------
    // In order to discern between a message accepted as a queryable write and
    // something accepted as an initial state we use separate response codes:
    //   - 202 for queryable writes
    //   - 204 for non-queryable writes.
    //   - 409 if the incoming message is not the latest (TODO: used typed errors)
    //
    // See https://github.com/TBD54566975/dwn-sdk-js/issues/695 for more details.

    // has data stream been provided?
    // if data_stream.is_some() {
    //    (process_with_data_stream(owner, message, data_stream).await?,
    //     true)
    // } else

    // if the incoming message is not the initial write, and no `data_stream` is
    // set, we can process
    let (write, code) = if initial.is_some() {
        let Some(latest) = &latest else {
            return Err(anyhow!("newest existing message not found"));
        };
        let write = process_data(&ctx.owner, &write, latest, &provider).await?;
        (write, 202)
    } else {
        (write, 204)
    };

    // save the message and log
    let cid = cid::compute(&write)?;
    let message = Message::RecordsWrite(write.clone());

    MessageStore::put(&provider, &ctx.owner, &message).await?;
    EventLog::append(&provider, &ctx.owner, &cid, &message).await?;

    // only emit an event when the message is the latest base state
    if initial.is_some() {
        let initial_entry = initial.map(Message::RecordsWrite);
        let event = Event {
            message,
            initial_entry,
        };
        EventStream::emit(&provider, &ctx.owner, &event).await?;
    }

    // delete messages with the same `record_id` EXCEPT the initial write
    let mut deletable = VecDeque::from(messages);
    let _ = deletable.pop_front(); // initial write is first entry
    for msg in deletable {
        let cid = cid::compute(&msg)?;
        MessageStore::delete(&provider, &ctx.owner, &cid).await?;
        EventLog::delete(&provider, &ctx.owner, &cid).await?;
    }

    // when message is a grant revocation, delete all grant-authorized
    // messages with timestamp after revocation
    if write.descriptor.protocol == Some(PROTOCOL_URI.to_owned())
        && write.descriptor.protocol_path == Some(REVOCATION_PATH.to_owned())
    {
        revoke_grants(&ctx.owner, &write, &provider).await?;
    }

    Ok(WriteReply { code })
}

async fn authorize(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let authzn = &write.authorization;
    let record_owner = authzn.owner()?;

    // if owner signature is set, it must be the same as the tenant DID
    if record_owner.as_ref().is_some_and(|ro| ro != owner) {
        return Err(anyhow!("record owner is not web node owner"));
    };

    let author = authzn.author()?;

    // authorize author delegate
    if let Some(delegated_grant) = &authzn.author_delegated_grant {
        let signer = authzn.signer()?;
        let grant = delegated_grant.to_grant()?;
        grant.permit_records_write(&author, &signer, write, store).await?;
    }

    // authorize owner delegate
    if let Some(delegated_grant) = &authzn.owner_delegated_grant {
        let Some(owner) = &record_owner else {
            return Err(anyhow!("owner is required to authorize owner delegate"));
        };
        let signer = authzn.owner_signer()?;
        let grant = delegated_grant.to_grant()?;
        grant.permit_records_write(owner, &signer, write, store).await?;
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
        return grant.permit_records_write(owner, &author, write, store).await;
    };

    // protocol-specific authorization
    if write.descriptor.protocol.is_some() {
        return protocol::permit_write(owner, write, store).await;
    }

    Err(anyhow!("message failed authorization"))
}

/// Records write message payload
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Write {
    /// The Write descriptor.
    pub descriptor: WriteDescriptor,

    /// The message authorization.
    pub authorization: Authorization,

    /// Record CID
    pub record_id: String,

    /// Record context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Record data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Record encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionProperty>,

    /// The base64url encoded data of the record if the data associated with
    /// the recordnis equal or smaller than `MAX_ENCODING_SIZE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,
}

impl Write {
    /// Signs the Write message body. The signer is either the author or a delegate.
    async fn sign(
        &mut self, delegated_grant: Option<DelegatedGrant>, permission_grant_id: Option<String>,
        protocol_role: Option<String>, signer: &impl Signer,
    ) -> Result<()> {
        let (author_did, delegated_grant_id) = if let Some(grant) = &delegated_grant {
            let signature = &grant.authorization.signature.signatures[0];
            let Some(kid) = signature.protected.kid() else {
                return Err(anyhow!("missing key ID"));
            };
            (kid.split('#').next().map(ToString::to_string), Some(cid::compute(&grant)?))
        } else {
            (signer.verification_method().split('#').next().map(ToString::to_string), None)
        };

        let descriptor_cid = cid::compute(&self.descriptor)?;

        // compute `record_id` if not given at construction time
        if self.record_id.is_empty() {
            #[derive(Serialize)]
            struct EntryIdInput {
                #[serde(flatten)]
                descriptor: WriteDescriptor,
                author: String,
            }
            let id_input = EntryIdInput {
                descriptor: self.descriptor.clone(),
                author: author_did.unwrap_or_default(),
            };
            self.record_id = cid::compute(&id_input)?;
        }

        // compute `context_id` if this is a protocol-space record
        if self.descriptor.protocol.is_some() {
            self.context_id = if let Some(parent_id) = &self.descriptor.parent_id {
                Some(format!("{parent_id}/{}", self.record_id))
            } else {
                Some(self.record_id.clone())
            };
        }

        let attestation_cid = if let Some(attestation) = &self.attestation {
            Some(cid::compute(attestation)?)
        } else {
            None
        };
        let encryption_cid = if let Some(encryption) = &self.encryption {
            Some(cid::compute(encryption)?)
        } else {
            None
        };

        let payload = WriteSignaturePayload {
            base: JwsPayload {
                descriptor_cid,
                permission_grant_id,
                delegated_grant_id,
                protocol_role,
            },
            record_id: self.record_id.clone(),
            context_id: self.context_id.clone(),
            attestation_cid,
            encryption_cid,
        };

        let jws = Jws::new(Type::Jwt, &payload, signer).await?;

        self.authorization = Authorization {
            signature: jws,
            author_delegated_grant: delegated_grant,
            ..Authorization::default()
        };

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
            return Err(anyhow!("message signature is required in order to sign as owner"));
        }

        let payload = JwsPayload {
            descriptor_cid: cid::compute(&self.descriptor)?,
            ..JwsPayload::default()
        };
        let owner_jws = Jws::new(Type::Jwt, &payload, signer).await?;
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
            return Err(anyhow!("signature is required in order to sign as owner delegate"));
        }

        //  descriptorCid, delegatedGrantId, permissionGrantId, protocolRole

        let delegated_grant_id = cid::compute(&delegated_grant)?;
        let descriptor_cid = cid::compute(&self.descriptor)?;

        let payload = JwsPayload {
            descriptor_cid,
            delegated_grant_id: Some(delegated_grant_id),
            ..JwsPayload::default()
        };
        let owner_jws = Jws::new(Type::Jwt, &payload, signer).await?;

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
                return Err(anyhow!(
                    "`protocol` must be specified to use `protocols` encryption scheme"
                ));
            }
            if key.derivation_scheme == Some(DerivationScheme::Schemas)
                && self.descriptor.schema.is_none()
            {
                return Err(anyhow!(
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

    // Computes the deterministic Entry ID of the message.
    pub(crate) fn entry_id(&self) -> Result<String> {
        let author = self.authorization.author()?;
        let mut descriptor = self.descriptor.clone();
        descriptor.author = Some(author);
        cid::compute(&descriptor)
    }

    pub(crate) fn is_initial(&self) -> Result<bool> {
        Ok(self.entry_id()? == self.record_id)
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

    //
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
    type Error = anyhow::Error;

    fn try_from(value: DelegatedGrant) -> Result<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(&value.encoded_data)?;
        let mut grant: Self = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("issue deserializing grant: {e}"))?;

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
    pub data_size: u64,

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

    // TODO: fix this
    /// used to calculate CID during test for intial write.
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<String>,
}

/// Write reply.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WriteReply {
    #[serde(skip)]
    pub(crate) code: u16,
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

    /// Data CID.
    Cid {
        /// CID of data already stored by the web node. If not set, the `data`
        /// parameter must be set.
        data_cid: String,

        /// Size of the `data` attribute in bytes. Must be set when `data_cid` is set,
        /// otherwise should be left unset.
        data_size: u64,
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

#[derive(Serialize)]
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
        // CID
        let (data_cid, data_size) = match self.data {
            WriteData::Cid { data_cid, data_size } => (data_cid, data_size),
            WriteData::Bytes { data } => {
                let data_cid = cid::compute(&data)?;
                let data_size = data.len() as u64;
                (data_cid, data_size)
            }
        };

        // timestamp
        let timestamp = self.message_timestamp.unwrap_or_else(Utc::now);

        let mut descriptor = WriteDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Write,
                message_timestamp: Some(timestamp),
            },
            recipient: self.recipient,
            tags: self.tags,
            data_cid,
            data_size,
            date_created: self.date_created.unwrap_or(timestamp),
            published: self.published,
            data_format: self.data_format,
            parent_id: self.parent_context_id.clone(),
            ..WriteDescriptor::default()
        };

        // protocol, protoco_ path
        if let Some(p) = self.protocol {
            let normalized = utils::clean_url(&p.protocol)?;
            descriptor.protocol = Some(normalized);
            descriptor.protocol_path = Some(p.protocol_path);
        }

        // schema
        if let Some(s) = self.schema {
            descriptor.schema = Some(utils::clean_url(&s)?);
        }

        // parent_id - first segment of  `parent_context_id`
        if let Some(id) = self.parent_context_id {
            let parent_id = id.split('/').find(|s| !s.is_empty()).map(ToString::to_string);
            descriptor.parent_id = parent_id;
        }

        // set `date_published`
        if self.published.unwrap_or_default() && self.date_published.is_none() {
            descriptor.date_published = Some(timestamp);
        }

        // attestation
        let payload = Payload {
            descriptor_cid: cid::compute(&descriptor)?,
        };
        let jws = Jws::new(Type::Jwt, &payload, keyring).await?;

        // encryption

        let mut write = Write {
            record_id: self.record_id.unwrap_or_default(),
            descriptor,
            attestation: Some(jws),
            ..Write::default()
        };

        if let Some(ecryption_input) = &self.encryption_input {
            write.encrypt(ecryption_input, keyring).await?;
        }

        // sign message
        write
            .sign(self.delegated_grant, self.permission_grant_id, self.protocol_role, keyring)
            .await?;

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
) -> Result<Vec<Message>> {
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{record_id}'
        ORDER BY descriptor.messageTimestamp ASC
        ",
        interface = Interface::Records,
        method = Method::Write,
    );
    let (records, _) = store.query(owner, &sql).await?;
    Ok(records)
}

// Fetches the first and last `records::Write` messages associated for the
// `record_id`.
pub(crate) async fn first_and_last(messages: &[Message]) -> Result<(Option<Write>, Option<Write>)> {
    // get initial entry
    let initial = if let Some(initial) = messages.first() {
        let Message::RecordsWrite(entry) = initial else {
            return Err(anyhow!("unexpected message type"));
        };
        // check initial write is found
        if !entry.is_initial()? {
            return Err(anyhow!("initial write is not earliest message"));
        }
        Some(entry)
    } else {
        None
    };

    // get latest entry
    let latest = if let Some(latest) = messages.last() {
        let Message::RecordsWrite(entry) = latest else {
            return Err(anyhow!("unexpected message type"));
        };
        Some(entry)
    } else {
        None
    };

    Ok((initial.cloned(), latest.cloned()))
}

// Write message is not an 'initial write' with no data_stream.
// Check integrity against the most recent existing write.
async fn process_data(
    owner: &str, write: &Write, existing: &Write, store: &impl DataStore,
) -> Result<Write> {
    // Perform `data_cid` check in case a user attempts to gain access to data
    // by referencing a different known `data_cid`. This  ensures the data is
    // already associated with the latest existing message.
    // See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info
    if existing.descriptor.data_cid != write.descriptor.data_cid {
        return Err(anyhow!("data CID does not match data_cid in descriptor"));
    }
    if existing.descriptor.data_size != write.descriptor.data_size {
        return Err(anyhow!("data size does not match dta_size in descriptor"));
    }

    // encode the data from the original write if it is smaller than the
    // data-store threshold
    let mut message = write.clone();
    if write.descriptor.data_size <= MAX_ENCODED_SIZE {
        let Some(encoded) = &existing.encoded_data else {
            return Err(anyhow!("no `encoded_data` in most recent existing message"));
        };
        message.encoded_data = Some(encoded.clone());
    };

    // otherwise, make sure the data is in the data store
    let result = store.get(owner, &existing.record_id, &write.descriptor.data_cid).await?;
    if result.is_none() {
        return Err(anyhow!("`data_stream` not set and unable to get data from previous message"));
    };

    Ok(message)
}

// Revoke grants if records::Write is a permission revocation .
async fn revoke_grants(owner: &str, write: &Write, provider: &impl Provider) -> Result<()> {
    // get grant from revocation message `parent_id`
    let Some(grant_id) = &write.descriptor.parent_id else {
        return Err(anyhow!("missing `parent_id`"));
    };
    let message_timestamp = write.descriptor.base.message_timestamp.unwrap_or_default();

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{grant_id}'
        AND dateCreated >= '{message_timestamp}
        ",
        interface = Interface::Records,
        method = Method::Write,
    ); // AND isLatestBaseState = true

    let (messages, _) = MessageStore::query(provider, owner, &sql).await?;

    // delete any messages with the same `record_id` except the initial write
    for msg in messages {
        let cid = cid::compute(&msg)?;
        EventLog::delete(provider, owner, &cid).await?;
    }

    Ok(())
}
