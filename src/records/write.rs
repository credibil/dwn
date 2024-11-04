//! # Write
//!
//! `Write` is a message type used to create a new record in the DWN.

use std::cmp::Ordering;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::jose::{EncryptionAlgorithm, Jws, PublicKeyJwk, Type};
use vercre_infosec::{Cipher, Signer};

use crate::auth::{Authorization, JwsPayload};
use crate::permissions::{self, ScopeType};
use crate::provider::{DataStore, Keyring, MessageStore, Provider};
use crate::records::protocol;
use crate::service::{Context, Message};
use crate::{
    cid, protocols, utils, Cursor, Descriptor, Interface, Method, Status, MAX_ENCODED_SIZE,
};

/// Process `Write` message.
///
/// # Errors
/// TODO: Add errors
pub(crate) async fn handle(
    ctx: &Context, write: Write, provider: impl Provider,
) -> Result<WriteReply> {
    // Protocol-authorized record specific validation
    if write.descriptor.protocol.is_some() {
        protocol::verify_integrity(&ctx.owner, &write, &provider).await?;
    }

    authorize(&ctx.owner, &write, &provider).await?;

    // get `record_id` matches sorted by timestamp
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{record_id}'
        ORDER BY descriptor.messageTimestamp ASC
        ",
        interface = Interface::Records,
        method = Method::Write,
        record_id = write.record_id,
    );
    let (records, _) = MessageStore::query(&provider, &ctx.owner, &sql).await?;

    // get initial entry
    let initial_entry = if write.is_initial()? {
        None
    } else {
        let Some(Message::RecordsWrite(entry)) = records.first() else {
            return Err(anyhow!("unexpected message type"));
        };
        // check initial write is found
        if !entry.is_initial()? {
            return Err(anyhow!("initial write is not earliest message"));
        }
        // check immutable properties match
        if write.compare_immutable(entry) {
            return Err(anyhow!("immutable properties do not match"));
        }
        Some(entry)
    };

    // get latest entry
    let latest_entry = if let Some(latest) = records.last() {
        let Message::RecordsWrite(latest) = latest else {
            return Err(anyhow!("unexpected message type"));
        };
        // is our message older than the latest?
        let order =
            write.descriptor.base.message_timestamp.cmp(&latest.descriptor.base.message_timestamp);
        if order == Ordering::Less {
            return Err(anyhow!("newer message already exists"));
        }
        // is the latest message a delete?
        if latest.descriptor.base.method == Method::Delete {
            return Err(anyhow!("RecordsWrite not allowed after RecordsDelete"));
        }
        Some(latest)
    } else {
        None
    };

    // NOTE: We want to perform additional validation before storing the RecordsWrite.
    // This is necessary for core RecordsWrite that needs additional processing and
    // allows us to fail before the storing and post processing.
    write.preprocess(&ctx.owner, &provider).await?;

    // NOTE: We allow `isLatestBaseState` to be true ONLY if the incoming message
    // comes with data, or if the incoming message is NOT an initial write. This
    // would allow an initial write to be written to the DB without data, but
    // having it not queryable, because query implementation filters on
    // `isLatestBaseState` being `true` thus preventing a user's attempt to gain
    // authorized access to data by referencing the dataCid of a private data in
    // their initial writes,
    //
    // See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info

    // has data stream been provided?
    // if data_stream.is_some() {
    //    (process_with_data_stream(owner, message, data_stream).await?,
    //     true)
    // } else

    // if the incoming message is not an initial write, and no data_stream is
    // provided, we would allow it provided it passes validation
    let (reply_entry, is_latest_base_state) = if initial_entry.is_some() {
        let Some(latest) = latest_entry else {
            return Err(anyhow!("newest existing message not found"));
        };
        (process_data(&ctx.owner, &write, latest, &provider).await?, true)
    } else {
        (
            ReplyEntry {
                message: write.clone(),
                ..ReplyEntry::default()
            },
            false,
        )
    };

    //       MessageStore::put(&provider, owner, reply_entry).await?;
    //       EventLog.append(&provider,owner, await Message.getCid(message), indexes);

    //       // NOTE: We only emit a `RecordsWrite` when the message is the latest base state.
    //       // Because we allow a `RecordsWrite` which is not the latest state to be written, but not queried, we shouldn't emit it either.
    //       // It will be emitted as a part of a subsequent next write, if it is the latest base state.
    //       if (this.eventStream !== undefined && isLatestBaseState) {
    //         this.eventStream.emit(tenant, { message, initialWrite }, indexes);
    //       }

    //       const e = error as any;
    //       if (e.code !== undefined) {
    //         if (e.code === DwnErrorCode.RecordsWriteMissingEncodedDataInPrevious ||
    //           e.code === DwnErrorCode.RecordsWriteMissingDataInPrevious ||
    //           e.code === DwnErrorCode.RecordsWriteNotAllowedAfterDelete ||
    //           e.code === DwnErrorCode.RecordsWriteDataCidMismatch ||
    //           e.code === DwnErrorCode.RecordsWriteDataSizeMismatch ||
    //           e.code.startsWith('PermissionsProtocolValidate') ||
    //           e.code.startsWith('SchemaValidator')) {
    //           return messageReplyFromError(error, 400);
    //         }
    //       }
    //     }

    // In order to discern between something that was accepted as a queryable write and something that was accepted
    // as an initial state we use separate response codes. See https://github.com/TBD54566975/dwn-sdk-js/issues/695
    // for more details.
    // let reply= Reply  {
    //     status: (newMessageIsInitialWrite && dataStream === undefined) ?
    //     { code: 204, detail: 'No Content' } :
    //     { code: 202, detail: 'Accepted' }
    // };

    // delete all existing messages of the same record that are not newest, except for the initial write
    // StorageController.deleteAllOlderMessagesButKeepInitialWrite(
    //     tenant, records, newestMessage, this.messageStore, this.dataStore, this.eventLog
    // );

    // this.postProcessingForCoreRecordsWrite(tenant, recordsWrite);

    Ok(WriteReply {
        status: Status {
            code: 202,
            detail: Some("Accepted".to_string()),
        },
        ..WriteReply::default()
    })
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

// TODO:figure out what isLatestBaseState is
// We allow `isLatestBaseState` to be true ONLY if the incoming message comes
// with data, or if the incoming message is NOT an initial write. This would allow
// an initial write to be written to the DB without data, but having it not queryable,
// because query implementation filters on `isLatestBaseState` being `true`
// thus preventing a user's attempt to gain authorized access to data by referencing
// the dataCid of a private data in their initial writes,
// See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Record data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Record encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionProperty>,

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

    /// Signs the `RecordsWrite` as the DWN owner.
    ///
    /// This is used when the DWN owner wants to retain a copy of a message that
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

    // Performs additional validation before storing the RecordsWrite if it is
    // a core RecordsWrite that needs additional processing.
    async fn preprocess(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        // Ensure the protocol tag of a permission revocation RecordsWrite and
        // the parent grant's scoped protocol match.
        if self.descriptor.protocol == Some(protocols::PROTOCOL_URI.to_owned())
            && self.descriptor.protocol_path == Some(protocols::REVOCATION_PATH.to_owned())
        {
            // get grant from revocation message `parent_id`
            let Some(grant_id) = &self.descriptor.parent_id else {
                return Err(anyhow!("missing `parent_id`"));
            };
            let grant = permissions::fetch_grant(owner, grant_id, store).await?;

            // compare revocation message protocol and grant scope protocol
            if let Some(tags) = &self.descriptor.tags {
                let revoke_protocol =
                    tags.get("protocol").map_or("", |p| p.as_str().unwrap_or_default());

                let ScopeType::Records { protocol, .. } = grant.data.scope.scope_type else {
                    return Err(anyhow!("missing protocol in grant scope"));
                };

                if protocol != revoke_protocol {
                    return Err(anyhow!("revocation protocol {revoke_protocol} does not match grant protocol {protocol}"));
                }
            }
        }
        Ok(())
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

/// Records Write reply
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct WriteReply {
    /// Status message to accompany the reply.
    pub status: Status,

    /// The Query descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<String>>,

    /// The message authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
}

/// Data structure returned in a `RecordsQuery` reply entry.
///
/// NOTE: the message structure is a modified version of the message received,
/// the most notable differences are:
///   1. May include an initial `RecordsWrite` message
///   2. May include encoded data
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplyEntry {
    /// The write record
    message: Write,

    /// The initial write of the record if the returned `RecordsWrite` message
    /// is not the initial write.
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_entry: Option<Write>,

    /// The encoded data of the record if the data associated with the record
    /// is equal or smaller than `MAX_ENCODING_SIZE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    encoded_data: Option<String>,
}

// Fetches the initial records::Write message associated with the given (owner + recordId).
pub(crate) async fn initial_entry(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Option<Write>> {
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
    if records.is_empty() {
        return Err(anyhow!("cannot find initial write"));
    }

    let Some(Message::RecordsWrite(entry)) = records.first() else {
        return Err(anyhow!("unexpected message type"));
    };
    // check first is initial write
    if !entry.is_initial()? {
        return Err(anyhow!("initial write is not earliest message"));
    }

    Ok(Some(entry.clone()))
}

// Write message is not an 'initial write' with no data_stream.
// Check integrity against the most recent existing write.
async fn process_data(
    owner: &str, write: &Write, existing: &Write, store: &impl DataStore,
) -> Result<ReplyEntry> {
    // Perform `data_cid` check in case a user attempts to gain access to data
    // by referencing a different known `data_cid`. This  ensures the data is
    // already associated with the latest_entry existing message.
    // See: https://github.com/TBD54566975/dwn-sdk-js/issues/359 for more info
    if existing.descriptor.data_cid != write.descriptor.data_cid {
        return Err(anyhow!("data CID does not match data_cid in descriptor"));
    }
    if existing.descriptor.data_size != write.descriptor.data_size {
        return Err(anyhow!("data size does not match dta_size in descriptor"));
    }

    let mut reply_entry = ReplyEntry {
        message: write.clone(),
        ..ReplyEntry::default()
    };

    // encode the data from the original write if it is smaller than the
    // data-store threshold
    if write.descriptor.data_size <= MAX_ENCODED_SIZE {
        let Some(encoded) = &existing.encoded_data else {
            return Err(anyhow!("no `encoded_data` in most recent existing message"));
        };
        reply_entry.encoded_data = Some(encoded.clone());
    };

    // otherwise, make sure the data is in the data store
    let result = store.get(owner, &existing.record_id, &write.descriptor.data_cid).await?;
    if result.is_none() {
        return Err(anyhow!("`data_stream` not set and unable to get data from previous message"));
    };

    Ok(reply_entry)
}
