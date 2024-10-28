//! # Write
//!
//! `Write` is a message type used to create a new record in the DWN.

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::{EncryptionAlgorithm, Jws, PublicKeyJwk, Type};
use vercre_infosec::{Cipher, Signer};

use crate::auth::{Authorization, SignaturePayload};
use crate::provider::Keyring;
use crate::service::Message;
use crate::{cid, permissions, utils, Descriptor, Interface, Method};

/// Records write payload
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
    pub context_id: Option<String>,

    /// Record data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Record encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,

    /// Message data, base64url encoded.
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
            base: SignaturePayload {
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
        // HACK: temporary solution to get the message author
        if Message::RecordsWrite(self.clone()).author().is_none() {
            // owner delegate needs to sign over `record_id` using author DID.
            return Err(anyhow!(
                "message signature is required in order to sign as owner delegate"
            ));
        }

        //  descriptorCid, delegatedGrantId, permissionGrantId, protocolRole

        let delegated_grant_id = cid::compute(&delegated_grant)?;
        let descriptor_cid = cid::compute(&self.descriptor)?;

        let payload = SignaturePayload {
            descriptor_cid,
            delegated_grant_id: Some(delegated_grant_id),
            ..SignaturePayload::default()
        };
        let owner_jws = Jws::new(Type::Jwt, &payload, signer).await?;

        self.authorization.owner_signature = Some(owner_jws);
        self.authorization.owner_delegated_grant = Some(delegated_grant);

        Ok(())
    }
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteSignaturePayload {
    /// The standard signature payload.
    #[serde(flatten)]
    pub base: SignaturePayload,

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
        let bytes = Base64UrlUnpadded::decode_vec(&self.encoded_data)?;
        let mut grant: permissions::Grant = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("issue deserializing grant: {e}"))?;

        grant.id.clone_from(&self.record_id);
        grant.grantor = self.authorization.signer()?;
        grant.grantee = self.descriptor.recipient.clone().unwrap_or_default();
        grant.date_granted.clone_from(&self.descriptor.date_created);

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
    pub date_created: String,

    /// Indicates whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// The datetime of publishing, if published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<String>,
}

/// Encryption settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Encryption {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The encrypted CEK.
    pub key_encryption: Vec<EncryptedKey>,
}

/// Encrypted key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the root public key used to encrypt the symmetric encryption key.
    pub root_key_d: String,

    /// The derived public key.
    pub derived_public_key: Option<PublicKeyJwk>,

    /// Encryption key derivation scheme.
    pub derivation_scheme: Option<KeyDerivationScheme>,

    /// The encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The ephemeral public key.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The MAC
    pub message_authentication_code: String,

    /// The encrypted key.
    pub encrypted_key: String,
}

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyDerivationScheme {
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
    date_created: Option<String>,
    message_timestamp: Option<String>,
    published: Option<bool>,
    date_published: Option<String>,
    data_format: String,
    delegated_grant: Option<DelegatedGrant>,
    encrypt: Option<bool>,
    permission_grant_id: Option<String>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    descriptor_cid: String,
}

impl WriteBuilder {
    /// Returns a new [`GrantBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now().to_rfc3339();

        // set defaults
        Self {
            date_created: Some(now.clone()),
            message_timestamp: Some(now),
            data_format: "application/json".to_string(),
            ..Self::default()
        }
    }

    /// Specify the write record's recipient .
    #[must_use]
    pub fn recipient(mut self, recipient: String) -> Self {
        self.recipient = Some(recipient);
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
    pub fn protocol_role(mut self, protocol_role: String) -> Self {
        self.protocol_role = Some(protocol_role);
        self
    }

    /// Specify a schema to use with the record.
    #[must_use]
    pub fn schema(mut self, schema: String) -> Self {
        self.schema = Some(schema);
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
    pub fn record_id(mut self, record_id: String) -> Self {
        self.record_id = Some(record_id);
        self
    }

    /// Required for a child (non-root) protocol record.
    #[must_use]
    pub fn parent_context_id(mut self, parent_context_id: String) -> Self {
        self.parent_context_id = Some(parent_context_id);
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
    pub fn date_created(mut self, date_created: String) -> Self {
        self.date_created = Some(date_created);
        self
    }

    /// The datetime the record was created. Defaults to now.
    #[must_use]
    pub fn message_timestamp(mut self, message_timestamp: String) -> Self {
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
    pub fn date_published(mut self, date_published: String) -> Self {
        self.date_published = Some(date_published);
        self
    }

    /// The record's MIME type. Defaults to `application/json`.
    #[must_use]
    pub fn data_format(mut self, data_format: String) -> Self {
        self.data_format = data_format;
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
    pub const fn encrypt(mut self, encrypt: bool) -> Self {
        self.encrypt = Some(encrypt);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: String) -> Self {
        self.permission_grant_id = Some(permission_grant_id);
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
        let timestamp = self.message_timestamp.unwrap_or_else(|| Utc::now().to_rfc3339());

        let mut descriptor = WriteDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Write,
                message_timestamp: Some(timestamp.clone()),
            },
            recipient: self.recipient,
            tags: self.tags,
            data_cid,
            data_size,
            date_created: self.date_created.unwrap_or_else(|| timestamp.clone()),
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
        let encryption = if self.encrypt.unwrap_or_default() {
            let encrypted = encrypt(&descriptor, keyring).await?;
            Some(encrypted)
        } else {
            None
        };

        let mut write = Write {
            record_id: self.record_id.unwrap_or_default(),
            descriptor,
            attestation: Some(jws),
            encryption,
            ..Write::default()
        };

        // sign message
        write
            .sign(self.delegated_grant, self.permission_grant_id, self.protocol_role, keyring)
            .await?;

        Ok(write)
    }
}

/// Encrypt message
async fn encrypt(_descriptor: &WriteDescriptor, _encryptor: &impl Cipher) -> Result<Encryption> {
    // encrypt the data encryption key once per encryption input

    //     const keyEncryption: EncryptedKey[] = [];
    //     for (const keyEncryptionInput of encryptionInput.keyEncryptionInputs) {
    //       if (keyEncryptionInput.derivationScheme === KeyDerivationScheme.ProtocolPath && descriptor.protocol === undefined) {
    //         throw new DwnError(
    //           DwnErrorCode.RecordsWriteMissingProtocol,
    //           '`protocols` encryption scheme cannot be applied to record without the `protocol` property.'
    //         );
    //       }

    //       if (keyEncryptionInput.derivationScheme === KeyDerivationScheme.Schemas && descriptor.schema === undefined) {
    //         throw new DwnError(
    //           DwnErrorCode.RecordsWriteMissingSchema,
    //           '`schemas` encryption scheme cannot be applied to record without the `schema` property.'
    //         );
    //       }

    //       // NOTE: right now only `ECIES-ES256K` algorithm is supported for asymmetric encryption,
    //       // so we will assume that's the algorithm without additional switch/if statements
    //       const publicKeyBytes = Secp256k1.publicJwkToBytes(keyEncryptionInput.publicKey);
    //       const keyEncryptionOutput = await Encryption.eciesSecp256k1Encrypt(publicKeyBytes, encryptionInput.key);

    //       const encryptedKey = Encoder.bytesToBase64Url(keyEncryptionOutput.ciphertext);
    //       const ephemeralPublicKey = await Secp256k1.publicKeyToJwk(keyEncryptionOutput.ephemeralPublicKey);
    //       const keyEncryptionInitializationVector = Encoder.bytesToBase64Url(keyEncryptionOutput.initializationVector);
    //       const messageAuthenticationCode = Encoder.bytesToBase64Url(keyEncryptionOutput.messageAuthenticationCode);
    //       const encryptedKeyData: EncryptedKey = {
    //         rootKeyId            : keyEncryptionInput.publicKeyId,
    //         algorithm            : keyEncryptionInput.algorithm ?? EncryptionAlgorithm.EciesSecp256k1,
    //         derivationScheme     : keyEncryptionInput.derivationScheme,
    //         ephemeralPublicKey,
    //         initializationVector : keyEncryptionInitializationVector,
    //         messageAuthenticationCode,
    //         encryptedKey
    //       };

    //       // we need to attach the actual public key if derivation scheme is protocol-context,
    //       // so that the responder to this message is able to encrypt the message/symmetric key using the same protocol-context derived public key,
    //       // without needing the knowledge of the corresponding private key
    //       if (keyEncryptionInput.derivationScheme === KeyDerivationScheme.ProtocolContext) {
    //         encryptedKeyData.derivedPublicKey = keyEncryptionInput.publicKey;
    //       }

    //       keyEncryption.push(encryptedKeyData);
    //     }

    //     const encryption: EncryptionProperty = {
    //       algorithm            : encryptionInput.algorithm ?? EncryptionAlgorithm.Aes256Ctr,
    //       initializationVector : Encoder.bytesToBase64Url(encryptionInput.initializationVector),
    //       keyEncryption
    //     };

    //     return encryption;

    todo!()
}
