//! # Write
//!
//! `Write` is a message type used to create a new record in the web node.

use std::collections::VecDeque;
use std::io::Read;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::format::SecondsFormat;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::Signer;
use vercre_infosec::jose::jwe::{ContentAlgorithm, KeyAlgorithm};
use vercre_infosec::jose::{Jws, JwsBuilder, PublicKeyJwk};

use crate::authorization::{self, Authorization, JwsPayload};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::hd_key::DerivationScheme;
use crate::permissions::{self, Grant, Protocol};
use crate::protocols::{PROTOCOL_URI, REVOCATION_PATH, integrity};
use crate::provider::{BlockStore, EventLog, EventStream, MessageStore, Provider};
use crate::records::{DataStream, DateRange};
use crate::serde::{rfc3339_micros, rfc3339_micros_opt};
use crate::store::{Entry, EntryType, RecordsFilter, RecordsQuery};
use crate::{Descriptor, Error, Interface, Method, Result, data, forbidden, unexpected, utils};

/// Handle `RecordsWrite` messages.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, write: Write, provider: &impl Provider,
) -> Result<Reply<WriteReply>> {
    write.authorize(owner, provider).await?;

    // verify integrity of messages with protocol
    if write.descriptor.protocol.is_some() {
        integrity::verify(owner, &write, provider).await?;
    }

    let existing = existing_entries(owner, &write.record_id, provider).await?;
    let (initial_entry, latest_entry) = earliest_and_latest(&existing);

    // when message is not the initial write, verify 'immutable' properties
    if let Some(initial_entry) = &initial_entry {
        let initial_write = Write::try_from(initial_entry)?;
        if !initial_write.is_initial()? {
            return Err(unexpected!("initial write is not earliest message"));
        }
        write.compare_immutable(&initial_write)?;
    }

    // confirm current message is the most recent AND previous write was not a 'delete'
    if let Some(latest_entry) = &latest_entry {
        let write_ts = write.descriptor.base.message_timestamp.timestamp_micros();
        let latest_ts = latest_entry.descriptor().message_timestamp.timestamp_micros();
        if write_ts < latest_ts {
            return Err(Error::Conflict("newer write record already exists".to_string()));
        }

        if latest_entry.descriptor().method == Method::Delete {
            return Err(unexpected!("RecordsWrite not allowed after RecordsDelete"));
        }
    }

    let (write, code) = if let Some(mut data) = write.data_stream.clone() {
        // incoming message WITH data
        (process_stream(owner, &write, &mut data, provider).await?, StatusCode::ACCEPTED)
    } else if initial_entry.is_some() {
        // incoming message WITHOUT data AND not an initial write
        let Some(latest_entry) = &latest_entry else {
            return Err(unexpected!("latest existing message should exist"));
        };
        let latest_write = Write::try_from(latest_entry)?;
        (process_data(owner, &write, &latest_write, provider).await?, StatusCode::ACCEPTED)
    } else {
        // incoming message WITHOUT data AND an initial write
        (write, StatusCode::NO_CONTENT)
    };

    // ----------------------------------------------------------------
    // Archive
    // ----------------------------------------------------------------
    // The `archive` flag is set when the intial write has no data.
    // It prevents querying of initial writes without data, thus preventing users
    // from accessing private data they wouldn't ordinarily be able to access.
    let mut entry = Entry::from(&write);
    entry.indexes.insert("archived".to_string(), Value::Bool(code == StatusCode::NO_CONTENT));

    // save the message and log the event
    MessageStore::put(provider, owner, &entry).await?;
    EventLog::append(provider, owner, &entry).await?;
    EventStream::emit(provider, owner, &entry).await?;

    // when this is an update, archive the initial write (and delete its data?)
    if let Some(initial_entry) = initial_entry {
        let initial_write = Write::try_from(&initial_entry)?;

        let mut entry = initial_entry;
        entry.indexes.insert("archived".to_string(), Value::Bool(true));

        MessageStore::put(provider, owner, &entry).await?;
        // FIXME: event_log data should be immutable
        EventLog::append(provider, owner, &entry).await?;
        BlockStore::delete(provider, owner, &initial_write.descriptor.data_cid).await?;
    }

    // delete any previous messages with the same `record_id` EXCEPT initial write
    let mut deletable = VecDeque::from(existing);
    let _ = deletable.pop_front(); // initial write is first entry
    for entry in deletable {
        let write = Write::try_from(entry)?;
        let cid = write.cid()?;
        MessageStore::delete(provider, owner, &cid).await?;
        BlockStore::delete(provider, owner, &write.descriptor.data_cid).await?;
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
    // In order to discern between a 'private' write and an accessible initial
    // state we use separate response codes:
    //   - 202 for queryable writes
    //   - 204 for private, non-queryable writes
    Ok(Reply {
        status: Status {
            code: code.as_u16(),
            detail: None,
        },
        body: None,
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

    /// Entry CID
    pub record_id: String,

    /// Entry context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Entry attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,

    /// Entry encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionProperty>,

    /// The base64url encoded data of the record if the data associated with
    /// the record is equal or smaller than `MAX_ENCODING_SIZE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded_data: Option<String>,

    /// The data stream of the record if the data associated with the record
    #[serde(skip)]
    pub data_stream: Option<DataStream>,
}

impl Message for Write {
    type Reply = WriteReply;

    fn cid(&self) -> Result<String> {
        // exclude `record_id` and `context_id` from CID calculation
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

    async fn handle(self, owner: &str, provider: &impl Provider) -> Result<Reply<Self::Reply>> {
        // FIXME: fix this lint
        #[allow(clippy::large_futures)]
        handle(owner, self, provider).await
    }
}

/// `Write` reply
// #[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct WriteReply;

impl TryFrom<Entry> for Write {
    type Error = crate::Error;

    fn try_from(entry: Entry) -> Result<Self> {
        match entry.message {
            EntryType::Write(write) => Ok(write),
            _ => Err(unexpected!("expected `RecordsWrite` message")),
        }
    }
}

impl TryFrom<&Entry> for Write {
    type Error = crate::Error;

    fn try_from(entry: &Entry) -> Result<Self> {
        match &entry.message {
            EntryType::Write(write) => Ok(write.clone()),
            _ => Err(unexpected!("expected `RecordsWrite` message")),
        }
    }
}

impl Write {
    /// Use a builder to create a new [`Write`] message.
    #[must_use]
    pub fn build() -> WriteBuilder<New, Unattested, Unsigned> {
        WriteBuilder::new()
    }

    /// Add a data stream to the write message.
    pub fn with_stream(&mut self, data_stream: DataStream) {
        self.data_stream = Some(data_stream);
    }

    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let record_owner = authzn.owner()?;

        // if owner signature is set, it must be the same as the tenant DID
        if record_owner.as_ref().is_some_and(|ro| ro != owner) {
            return Err(forbidden!("record owner is not web node owner"));
        };

        let author = authzn.author()?;

        // authorize author delegate
        if let Some(delegated_grant) = &authzn.author_delegated_grant {
            let signer = authzn.signer()?;
            let grant = delegated_grant.to_grant()?;
            grant.permit_write(&author, &signer, self, store).await?;
        }

        // authorize owner delegate
        if let Some(delegated_grant) = &authzn.owner_delegated_grant {
            let Some(owner) = &record_owner else {
                return Err(forbidden!("owner is required to authorize owner delegate"));
            };
            let signer = authzn.owner_signer()?;
            let grant = delegated_grant.to_grant()?;
            grant.permit_write(owner, &signer, self, store).await?;
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
            return grant.permit_write(owner, &author, self, store).await;
        };

        // protocol-specific authorization
        if let Some(protocol) = &self.descriptor.protocol {
            let protocol = Protocol::new(protocol).context_id(self.context_id.as_ref());
            return protocol.permit_write(owner, self, store).await;
        }

        Err(forbidden!("message failed authorization"))
    }

    /// Signs the Write message body. The signer is either the author or a delegate.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn sign_as_author(
        &mut self, parent_context_id: Option<String>, permission_grant_id: Option<String>,
        protocol_role: Option<String>, signer: &impl Signer,
    ) -> Result<()> {
        let (author_did, delegated_grant_id) = if let Some(grant) =
            &self.authorization.author_delegated_grant
        {
            (
                Some(authorization::signer_did(&grant.authorization.signature)?),
                Some(cid::from_value(&grant)?),
            )
        } else {
            // TODO: add helper method to Signer trait
            (signer.verification_method().await?.split('#').next().map(ToString::to_string), None)
        };

        // compute `record_id` when not provided
        if self.record_id.is_empty() {
            self.record_id =
                entry_id(self.descriptor.clone(), author_did.clone().unwrap_or_default())?;
        }

        // compute `context_id` if this is a protocol-space record
        if self.descriptor.protocol.is_some() {
            self.context_id = if let Some(parent_context_id) = parent_context_id {
                Some(format!("{parent_context_id}/{}", self.record_id))
            } else {
                Some(self.record_id.clone())
            };
        }

        // compute CIDs for attestation and encryption
        let attestation_cid = self.attestation.as_ref().map(cid::from_value).transpose()?;
        let encryption_cid = self.encryption.as_ref().map(cid::from_value).transpose()?;

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
    /// LATER: Add errors
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
    /// LATER: Add errors
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

    // Determine whether the record is the initial write.
    pub(crate) fn is_initial(&self) -> Result<bool> {
        let entry_id = entry_id(self.descriptor.clone(), self.authorization.author()?)?;
        Ok(entry_id == self.record_id)
    }

    // Verify immutable properties of two records are identical.
    fn compare_immutable(&self, other: &Self) -> Result<()> {
        let self_desc = &self.descriptor;
        let other_desc = &other.descriptor;

        if self_desc.base.interface != other_desc.base.interface
            || self_desc.base.method != other_desc.base.method
            || self_desc.protocol != other_desc.protocol
            || self_desc.protocol_path != other_desc.protocol_path
            || self_desc.recipient != other_desc.recipient
            || self_desc.schema != other_desc.schema
            || self_desc.parent_id != other_desc.parent_id
            || self_desc.date_created.to_rfc3339_opts(SecondsFormat::Micros, true)
                != other_desc.date_created.to_rfc3339_opts(SecondsFormat::Micros, true)
        {
            return Err(unexpected!("immutable properties do not match"));
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
    /// LATER: Add errors
    pub fn to_grant(&self) -> Result<Grant> {
        self.try_into()
    }
}

impl From<Write> for DelegatedGrant {
    fn from(write: Write) -> Self {
        Self {
            descriptor: write.descriptor,
            authorization: Box::new(write.authorization),
            record_id: write.record_id,
            context_id: write.context_id,
            encoded_data: write.encoded_data.unwrap_or_default(),
        }
    }
}

/// Write descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteDescriptor {
    /// The base descriptor
    #[serde(flatten)]
    pub base: Descriptor,

    /// Entry's protocol.
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
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_created: DateTime<Utc>,

    /// Indicates whether the record is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// The datetime of publishing, if published.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rfc3339_micros_opt")]
    pub date_published: Option<DateTime<Utc>>,
}

/// `EncryptionProperty` contains information about the encryption used when
/// encrypting a `Write` message. The information is used by the recipient
/// to decrypt the message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProperty {
    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `enc` property).
    pub algorithm: ContentAlgorithm,

    /// The initialization vector used to encrypt the data.
    pub initialization_vector: String,

    /// One or more objects, each containing information about the
    /// Content Encryption Key (CEK) used to encrypt the data.
    pub key_encryption: Vec<EncryptedKey>,
}

/// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
/// Encrypted Key (JWE `encrypted_key` property), this is the key used to
/// encrypt the data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id)
    /// of the root public key used to encrypt the symmetric encryption key.
    pub root_key_id: String,

    /// The derived public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_public_key: Option<PublicKeyJwk>,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,

    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `alg` property).
    pub algorithm: KeyAlgorithm,

    /// The ephemeral public key used to encrypt the data.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The initialization vector used to encrypt the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<String>,

    /// The message authentication code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_authentication_code: Option<String>,

    /// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
    /// Encrypted Key (JWE `encrypted_key` property), this is the key used to
    /// encrypt the data.
    pub encrypted_key: String,
}

/// Options for use when creating a new [`Write`] message.
pub struct WriteBuilder<O, A, S> {
    message_timestamp: DateTime<Utc>,
    recipient: Option<String>,
    protocol: Option<WriteProtocol>,
    schema: Option<String>,
    tags: Option<Map<String, Value>>,
    record_id: Option<String>,
    parent_context_id: Option<String>,
    data: Data,
    data_format: String,
    date_created: DateTime<Utc>,
    published: Option<bool>,
    date_published: Option<DateTime<Utc>>,
    protocol_role: Option<String>,
    permission_grant_id: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    existing: Option<Write>,
    origin: O,
    attesters: A,
    signer: S,
}

impl Default for WriteBuilder<New, Unattested, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// The protocol to use for the Write message.
#[derive(Clone, Debug, Default)]
pub struct WriteProtocol {
    /// Entry protocol.
    pub protocol: String,

    /// Protocol path.
    pub protocol_path: String,
}

/// Entry data can be raw bytes or CID.
pub enum Data {
    /// Data is a `DataStream`.
    Stream(DataStream),

    /// A CID referencing previously stored data.
    Cid {
        /// CID of data already stored by the web node. If not set, the `data`
        /// parameter must be set.
        data_cid: String,

        /// Size of the `data` attribute in bytes. Must be set when `data_cid` is set,
        /// otherwise should be left unset.
        data_size: usize,
    },
}

impl Default for Data {
    fn default() -> Self {
        Self::Stream(DataStream::default())
    }
}

impl From<Vec<u8>> for Data {
    fn from(data: Vec<u8>) -> Self {
        Data::Stream(DataStream::from(data))
    }
}

// State 'guards' for the WriteBuilder typestate pattern.
pub struct New;
pub struct Existing;

pub struct Unattested;
pub struct Attested<'a, A: Signer>(pub &'a [&'a A]);

pub struct Unsigned;
pub struct Signed<'a, S: Signer>(pub &'a S);

/// Create a `Write` record from scratch.
impl WriteBuilder<New, Unattested, Unsigned> {
    /// Returns a new [`WriteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        Self {
            message_timestamp: now,
            date_created: now,
            data: Data::default(),
            data_format: "application/json".to_string(),
            signer: Unsigned,
            attesters: Unattested,
            origin: New,
            recipient: None,
            protocol: None,
            schema: None,
            tags: None,
            record_id: None,
            parent_context_id: None,
            published: None,
            date_published: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
            existing: None,
        }
    }
}

/// Create a [`Write`] record from an existing record.
impl WriteBuilder<Existing, Unattested, Unsigned> {
    /// Returns a new [`WriteBuilder`] based on an existing `Write` record.
    #[must_use]
    pub fn from(existing: Write) -> Self {
        Self {
            message_timestamp: Utc::now(),
            date_created: existing.descriptor.date_created,
            data: Data::default(),
            data_format: existing.descriptor.data_format.clone(),
            existing: Some(existing),
            origin: Existing,
            signer: Unsigned,
            attesters: Unattested,
            recipient: None,
            protocol: None,
            schema: None,
            tags: None,
            record_id: None,
            parent_context_id: None,
            published: None,
            date_published: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
        }
    }
}

/// State: New, Unattested, Unencrypted, and Unsigned.
///
/// Immutable properties are able be set.
impl WriteBuilder<New, Unattested, Unsigned> {
    /// Set a protocol for the record.
    #[must_use]
    pub fn protocol(mut self, protocol: WriteProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Specify a schema to use with the record.
    #[must_use]
    pub fn schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Specify the write record's recipient .
    #[must_use]
    pub fn recipient(mut self, recipient: impl Into<String>) -> Self {
        self.recipient = Some(recipient.into());
        self
    }

    /// Required for a child (non-root) protocol record.
    #[must_use]
    pub fn parent_context_id(mut self, parent_context_id: impl Into<String>) -> Self {
        self.parent_context_id = Some(parent_context_id.into());
        self
    }
}

/// State: Unattested, and Unsigned.
///
///  Mutable properties properties are able to be set for both new and existing
/// `Write` records.
impl<O> WriteBuilder<O, Unattested, Unsigned> {
    /// Entry data as a CID or raw bytes.
    #[must_use]
    pub fn data(mut self, data: Data) -> Self {
        self.data = data;
        self
    }

    /// The record's MIME type. Defaults to `application/json`.
    #[must_use]
    pub fn data_format(mut self, data_format: impl Into<String>) -> Self {
        self.data_format = data_format.into();
        self
    }

    /// Specify an ID to use for the permission request.
    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    /// Add a tag to the record.
    #[must_use]
    pub fn add_tag(mut self, name: String, value: Value) -> Self {
        self.tags.get_or_insert_with(Map::new).insert(name, value);
        self
    }

    /// Whether the record is published.
    #[must_use]
    pub const fn published(mut self, published: bool) -> Self {
        self.published = Some(published);
        self
    }

    /// Specify a protocol role for the record.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// The delegated grant used with this record.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    // ----------------------------------------------------------------
    // Methods enabled soley for testing
    // ----------------------------------------------------------------
    /// Override message timestamp.
    #[cfg(debug_assertions)]
    #[must_use]
    pub const fn message_timestamp(mut self, message_timestamp: DateTime<Utc>) -> Self {
        self.message_timestamp = message_timestamp;
        self
    }

    /// Override date created.
    #[cfg(debug_assertions)]
    #[must_use]
    pub const fn date_created(mut self, date_created: DateTime<Utc>) -> Self {
        self.date_created = date_created;
        self
    }

    /// Override date published.
    #[cfg(debug_assertions)]
    #[must_use]
    pub const fn date_published(mut self, date_published: DateTime<Utc>) -> Self {
        self.date_published = Some(date_published);
        self
    }
}

/// State: Unencrypted and Unsigned.
impl<'a, O, A> WriteBuilder<O, A, Unsigned> {
    /// Logically (from user POV), have an attester sign the record.
    ///
    /// At this point, the builder simply captures the attester for use in the
    /// final build step. Can only be done if the content hasn't been signed
    /// or encrypted.
    #[must_use]
    pub fn attest<S: Signer>(
        self, attesters: &'a [&'a S],
    ) -> WriteBuilder<O, Attested<'a, S>, Unsigned> {
        WriteBuilder {
            attesters: Attested(attesters),
            message_timestamp: self.message_timestamp,
            recipient: self.recipient,
            protocol: self.protocol,
            schema: self.schema,
            tags: self.tags,
            record_id: self.record_id,
            parent_context_id: self.parent_context_id,
            data: self.data,
            data_format: self.data_format,
            date_created: self.date_created,
            published: self.published,
            date_published: self.date_published,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
            existing: self.existing,
            origin: self.origin,
            signer: self.signer,
        }
    }
}

// State: Unsigned
impl<'a, O, A> WriteBuilder<O, A, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the final
    /// build step. Can only be done if the content hasn't been signed yet.
    #[must_use]
    pub fn sign(self, signer: &'a impl Signer) -> WriteBuilder<O, A, Signed<'a, impl Signer>> {
        WriteBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            recipient: self.recipient,
            protocol: self.protocol,
            schema: self.schema,
            tags: self.tags,
            record_id: self.record_id,
            parent_context_id: self.parent_context_id,
            data: self.data,
            data_format: self.data_format,
            date_created: self.date_created,
            published: self.published,
            date_published: self.date_published,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
            existing: self.existing,
            origin: self.origin,
            attesters: self.attesters,
        }
    }
}

// State: Signed.

/// Builder is ready to build once the `sign` step is complete (i.e. the Signer
/// is set).
impl<O, A, S: Signer> WriteBuilder<O, A, Signed<'_, S>> {
    fn to_write(&self) -> Result<Write> {
        let mut write = if let Some(write) = &self.existing {
            write.clone()
        } else {
            let mut write = Write {
                descriptor: WriteDescriptor {
                    base: Descriptor {
                        interface: Interface::Records,
                        method: Method::Write,
                        message_timestamp: self.message_timestamp,
                    },
                    date_created: self.date_created,
                    recipient: self.recipient.clone(),
                    ..WriteDescriptor::default()
                },
                ..Write::default()
            };

            // immutable properties
            if let Some(write_protocol) = self.protocol.clone() {
                let normalized = utils::clean_url(&write_protocol.protocol)?;
                write.descriptor.protocol = Some(normalized);
                write.descriptor.protocol_path = Some(write_protocol.protocol_path);
            }
            if let Some(s) = &self.schema {
                write.descriptor.schema = Some(utils::clean_url(s)?);
            }
            // parent_id == last segment of  `parent_context_id`
            if let Some(parent_context_id) = &self.parent_context_id {
                write.descriptor.parent_id =
                    parent_context_id.split('/').last().map(ToString::to_string);
            }
            write
        };

        write.descriptor.base.message_timestamp = self.message_timestamp;
        write.descriptor.data_format.clone_from(&self.data_format);

        // record_id
        if let Some(record_id) = self.record_id.clone() {
            write.record_id = record_id;
        }
        // tags
        if let Some(tags) = self.tags.clone() {
            write.descriptor.tags = Some(tags);
        }

        // published
        if let Some(published) = self.published {
            write.descriptor.published = Some(published);
        }
        // date_published - need to unset if `published` is false
        if write.descriptor.published.unwrap_or_default() {
            write.descriptor.date_published =
                Some(self.date_published.unwrap_or(self.message_timestamp));
        } else {
            write.descriptor.date_published = None;
        }

        match &self.data {
            Data::Stream(stream) => {
                let (data_cid, data_size) = stream.compute_cid()?;
                write.descriptor.data_cid = data_cid;
                write.descriptor.data_size = data_size;

                // if data_size <= data::MAX_ENCODED_SIZE {
                //     write.encoded_data = Some(Base64UrlUnpadded::encode_string(&stream.buffer));
                // } else {
                //     write.data_stream = Some(stream.clone());
                // }

                write.encryption = stream.encryption();
                write.data_stream = Some(stream.clone());
            }
            Data::Cid { data_cid, data_size } => {
                write.descriptor.data_cid.clone_from(data_cid);
                write.descriptor.data_size = *data_size;
            }
        };

        // write.encryption = self.data.encryption();
        write.authorization = Authorization {
            author_delegated_grant: self.delegated_grant.clone(),
            ..Authorization::default()
        };

        Ok(write)
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    descriptor_cid: String,
}

impl<O, A: Signer, S: Signer> WriteBuilder<O, Attested<'_, A>, Signed<'_, S>> {
    async fn attestation(self, descriptor: &WriteDescriptor) -> Result<Jws> {
        let payload = Payload {
            descriptor_cid: cid::from_value(descriptor)?,
        };
        let Some(attester) = self.attesters.0.first() else {
            return Err(unexpected!("attesters is empty"));
        };
        Ok(JwsBuilder::new().payload(payload).build(*attester).await?)
    }
}

/// State: Unattested, Unencrypted, and Signed.
impl<O, S: Signer> WriteBuilder<O, Unattested, Signed<'_, S>> {
    /// Build the `Write` message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self) -> Result<Write> {
        let mut write = self.to_write()?;
        write
            .sign_as_author(
                self.parent_context_id,
                self.permission_grant_id,
                self.protocol_role,
                self.signer.0,
            )
            .await?;
        Ok(write)
    }
}

/// State: Attested, and Signed.
impl<'a, O, A: Signer, S: Signer> WriteBuilder<O, Attested<'a, A>, Signed<'a, S>> {
    /// Build the `Write` message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self) -> Result<Write> {
        let signer = self.signer.0;
        let parent_context_id = self.parent_context_id.clone();
        let protocol_role = self.protocol_role.clone();
        let permission_grant_id = self.permission_grant_id.clone();

        let mut write = self.to_write()?;
        write.attestation = Some(self.attestation(&write.descriptor).await?);
        write.sign_as_author(parent_context_id, permission_grant_id, protocol_role, signer).await?;
        Ok(write)
    }
}

// Computes the deterministic Entry ID of the message.
pub fn entry_id(descriptor: WriteDescriptor, author: String) -> Result<String> {
    #[derive(Serialize)]
    struct EntryId {
        #[serde(flatten)]
        descriptor: WriteDescriptor,
        author: String,
    }
    cid::from_value(&EntryId { descriptor, author })
}

// Fetch previous entries for this record, ordered from earliest to latest.
async fn existing_entries(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Vec<Entry>> {
    // N.B. unset method in order to get Write and Delete messages
    let query = RecordsQuery::new()
        .add_filter(RecordsFilter::new().record_id(record_id))
        .include_archived(true)
        .method(None);
    let entries = store.query(owner, &query.into()).await.unwrap();
    Ok(entries)
}

// Fetches the initial_write record associated for `record_id`.
pub async fn initial_write(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Option<Write>> {
    let entries = existing_entries(owner, record_id, store).await?;

    // check initial write is found
    if let Some(entry) = entries.first() {
        let write = Write::try_from(entry)?;
        if !write.is_initial()? {
            return Err(unexpected!("initial write is not earliest message"));
        }
        Ok(Some(write))
    } else {
        Ok(None)
    }
}

// Fetches the first and last `records::Write` messages associated for the
// `record_id`.
fn earliest_and_latest(entries: &[Entry]) -> (Option<Entry>, Option<Entry>) {
    entries.first().map_or((None, None), |first| (Some(first.clone()), entries.last().cloned()))
}

async fn process_stream(
    owner: &str, write: &Write, data: &mut DataStream, store: &impl BlockStore,
) -> Result<Write> {
    let mut write = write.clone();

    // when data is below the threshold, store it within MessageStore
    if write.descriptor.data_size <= data::MAX_ENCODED_SIZE {
        // compute CID before reading (and consuming) the stream
        let (data_cid, data_size) = data.compute_cid()?;

        // read data from stream
        let mut data_bytes = Vec::new();
        data.read_to_end(&mut data_bytes)?;

        if write.descriptor.data_cid != data_cid {
            return Err(unexpected!("computed data CID does not match message `data_cid`"));
        }
        if write.descriptor.data_size != data_size {
            return Err(unexpected!("actual data size does not match message `data_size`"));
        }
        if write.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
            integrity::verify_schema(&write, &data_bytes)?;
        }

        write.descriptor.data_cid = data_cid;
        write.descriptor.data_size = data_bytes.len();
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&data_bytes));
    } else {
        let (data_cid, data_size) = data.to_store(owner, store).await?;

        // verify data CID and size
        if write.descriptor.data_cid != data_cid {
            return Err(unexpected!("computed data CID does not match message `data_cid`"));
        }
        if write.descriptor.data_size != data_size {
            return Err(unexpected!("actual data size does not match message `data_size`"));
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
    if write.descriptor.data_size <= data::MAX_ENCODED_SIZE {
        let Some(encoded) = &existing.encoded_data else {
            return Err(unexpected!("no `encoded_data` in most recent existing message"));
        };
        message.encoded_data = Some(encoded.clone());
    };

    // otherwise, make sure the data is in the data store
    let result = store.get(owner, &write.descriptor.data_cid).await?;
    if result.is_none() {
        return Err(unexpected!(
            "`data_stream` is not set and unable to find previously stored data"
        ));
    };

    Ok(message)
}

// Revoke grants if records::Write is a permission revocation.
async fn revoke_grants(owner: &str, write: &Write, provider: &impl Provider) -> Result<()> {
    // get grant from revocation message `parent_id`
    let Some(grant_id) = &write.descriptor.parent_id else {
        return Err(unexpected!("missing `parent_id`"));
    };
    let message_timestamp = write.descriptor.base.message_timestamp;

    let lt = DateRange::new().lt(message_timestamp);
    let query =
        RecordsQuery::new().add_filter(RecordsFilter::new().record_id(grant_id).date_created(lt));

    let records = MessageStore::query(provider, owner, &query.into()).await?;

    // delete matching messages
    for record in records {
        let message_cid = record.cid()?;
        MessageStore::delete(provider, owner, &message_cid).await?;
        EventLog::delete(provider, owner, &message_cid).await?;
    }

    Ok(())
}
