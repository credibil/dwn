//! # Write
//!
//! `Write` is a message type used to create a new record in the web node.

use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::format::SecondsFormat::Micros;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_infosec::Signer;
use vercre_infosec::jose::{Jws, JwsBuilder};

use crate::authorization::{Authorization, JwsPayload};
use crate::data::cid;
use crate::endpoint::{Message, Reply, Status};
use crate::permissions::{self, Grant, Protocol};
use crate::protocols::{PROTOCOL_URI, REVOCATION_PATH, integrity};
use crate::provider::{DataStore, EventLog, EventStream, MessageStore, Provider};
use crate::records::{DateRange, EncryptionProperty};
use crate::serde::{rfc3339_micros, rfc3339_micros_opt};
use crate::store::{Entry, EntryType, GrantedQueryBuilder, RecordsFilter, RecordsQueryBuilder};
use crate::{Descriptor, Error, Method, Result, authorization, data, forbidden, unexpected};

/// Handle `RecordsWrite` messages.
///
/// # Errors
/// LATER: Add errors
pub async fn handle(
    owner: &str, write: Write, provider: &impl Provider,
) -> Result<Reply<WriteReply>> {
    write.authorize(owner, provider).await?;
    write.verify_integrity(owner, provider).await?;

    let is_initial = write.is_initial()?;

    // find any existing entries for the `record_id`
    let existing = existing_entries(owner, &write.record_id, provider).await?;
    let (initial_entry, latest_entry) = earliest_and_latest(&existing);

    // when no existing entries, verify this write is the initial write
    if initial_entry.is_none() && !is_initial {
        return Err(unexpected!("initial write not found"));
    }

    // when message is an update, verify 'immutable' properties are unchanged
    if let Some(initial_entry) = &initial_entry {
        let earliest = Write::try_from(initial_entry)?;
        if !earliest.is_initial()? {
            return Err(unexpected!("initial write is not the earliest message"));
        }
        write.verify_immutable(&earliest)?;
    }

    // check message is the most recent AND most recent has not been deleted
    if let Some(latest_entry) = &latest_entry {
        let write_ts = write.descriptor.base.message_timestamp.timestamp_micros();
        let latest_ts = latest_entry.descriptor().message_timestamp.timestamp_micros();
        if write_ts < latest_ts {
            return Err(Error::Conflict("a more recent update exists".to_string()));
        }
        if write_ts == latest_ts && write.cid()? <= latest_entry.cid()? {
            return Err(Error::Conflict("an update with a larger CID already exists".to_string()));
        }
        if latest_entry.descriptor().method == Method::Delete {
            return Err(unexpected!("record has been deleted"));
        }
    }

    // process data stream
    let mut write = write;
    if let Some(mut data) = write.data_stream.clone() {
        write.update_data(owner, &mut data, provider).await?;
    } else if !is_initial {
        // no data AND NOT an initial write
        let Some(existing) = &latest_entry else {
            return Err(unexpected!("latest existing record not found"));
        };
        write.clone_data(owner, existing, provider).await?;
    };

    // response codes
    let code = if write.data_stream.is_some() || !is_initial {
        // queryable writes
        StatusCode::ACCEPTED
    } else {
        //  private, non-queryable writes
        StatusCode::NO_CONTENT
    };

    // set `archive` flag is set when the intial write has no data
    // N.B. this is used to prevent malicious access to another record's data
    let mut entry = Entry::from(&write);
    entry.indexes.insert("archived".to_string(), (code == StatusCode::NO_CONTENT).to_string());

    // save the message and log the event
    MessageStore::put(provider, owner, &entry).await?;
    EventLog::append(provider, owner, &entry).await?;
    EventStream::emit(provider, owner, &entry).await?;

    // when this is an update, archive the initial write (and delete its data?)
    if let Some(mut initial_entry) = initial_entry {
        let initial_write = Write::try_from(&initial_entry)?;
        initial_entry.indexes.insert("archived".to_string(), true.to_string());

        MessageStore::put(provider, owner, &initial_entry).await?;
        EventLog::append(provider, owner, &initial_entry).await?;
        if !initial_write.descriptor.data_cid.is_empty() && write.data_stream.is_some() {
            DataStore::delete(provider, owner, "<record_id>", &initial_write.descriptor.data_cid)
                .await?;
        }
    }

    // delete any previous messages with the same `record_id` EXCEPT initial write
    let mut deletable = VecDeque::from(existing);
    let _ = deletable.pop_front(); // retain initial write (first entry)
    for entry in deletable {
        let write = Write::try_from(entry)?;
        let cid = write.cid()?;
        MessageStore::delete(provider, owner, &cid).await?;
        DataStore::delete(provider, owner, "<record_id>", &write.descriptor.data_cid).await?;
        EventLog::delete(provider, owner, &cid).await?;
    }

    // when message is a grant revocation, delete grant-authorized messages
    // created after revocation
    if write.descriptor.protocol == Some(PROTOCOL_URI.to_string())
        && write.descriptor.protocol_path == Some(REVOCATION_PATH.to_string())
    {
        write.revoke_grants(owner, provider).await?;
    }

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
    pub data_stream: Option<Cursor<Vec<u8>>>,
}

impl Message for Write {
    type Reply = WriteReply;

    fn cid(&self) -> Result<String> {
        // // exclude `record_id` and `context_id` from CID calculation
        // #[derive(Serialize)]
        // struct Cid {
        //     #[serde(flatten)]
        //     descriptor: WriteDescriptor,
        //     authorization: Authorization,
        // }
        // cid::from_value(&Cid {
        //     descriptor: self.descriptor.clone(),
        //     authorization: self.authorization.clone(),
        // })

        let mut write = self.clone();
        write.encoded_data = None;
        cid::from_value(&write)
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
    /// Build flattened indexes for the write message.
    #[must_use]
    pub fn indexes(&self) -> HashMap<String, String> {
        let mut indexes = HashMap::new();
        let descriptor = &self.descriptor;

        indexes.insert("interface".to_string(), descriptor.base.interface.to_string());
        indexes.insert("method".to_string(), descriptor.base.method.to_string());
        indexes.insert("archived".to_string(), false.to_string());

        // FIXME: add these fields back when cut over to new indexes
        indexes.insert("record_id".to_string(), self.record_id.clone());
        if let Some(context_id) = &self.context_id {
            indexes.insert("contextId".to_string(), context_id.clone());
        }
        // TODO: remove this after cut over to new indexes
        indexes.insert("messageCid".to_string(), self.cid().unwrap_or_default());
        indexes.insert(
            "messageTimestamp".to_string(),
            descriptor.base.message_timestamp.to_rfc3339_opts(Micros, true),
        );

        // set to "false" when None
        let published = descriptor.published.unwrap_or_default();
        indexes.insert("published".to_string(), published.to_string());

        indexes.insert("dataFormat".to_string(), descriptor.data_format.clone());
        indexes.insert("dataCid".to_string(), descriptor.data_cid.clone());
        indexes.insert("dataSize".to_string(), format!("{:0>10}", descriptor.data_size));
        indexes.insert(
            "dateCreated".to_string(),
            descriptor.date_created.to_rfc3339_opts(Micros, true),
        );
        if let Some(recipient) = &descriptor.recipient {
            indexes.insert("recipient".to_string(), recipient.clone());
        }
        if let Some(protocol) = &descriptor.protocol {
            indexes.insert("protocol".to_string(), protocol.clone());
        }
        if let Some(protocol_path) = &descriptor.protocol_path {
            indexes.insert("protocolPath".to_string(), protocol_path.clone());
        }
        if let Some(schema) = &descriptor.schema {
            indexes.insert("schema".to_string(), schema.clone());
        }
        if let Some(parent_id) = &descriptor.parent_id {
            indexes.insert("parentId".to_string(), parent_id.clone());
        }
        if let Some(date_published) = &descriptor.date_published {
            indexes
                .insert("datePublished".to_string(), date_published.to_rfc3339_opts(Micros, true));
        }

        // special values
        indexes.insert("author".to_string(), self.authorization.author().unwrap_or_default());

        if let Ok(jws) = &self.authorization.payload() {
            if let Some(grant_id) = &jws.permission_grant_id {
                indexes.insert("permissionGrantId".to_string(), grant_id.clone());
            }
        }

        if let Some(attestation) = &self.attestation {
            let attester = authorization::signer_did(attestation).unwrap_or_default();
            indexes.insert("attester".to_string(), attester);
        }

        // TODO: convert all tags to String (not Value)
        // flatten tags for indexing
        if let Some(tags) = &self.descriptor.tags {
            for (k, v) in tags {
                indexes.insert(format!("tag.{k}"), v.as_str().unwrap_or_default().to_string());
            }
        }

        indexes
    }

    /// Add a data stream to the write message.
    pub fn with_stream(&mut self, data_stream: Cursor<Vec<u8>>) {
        self.data_stream = Some(data_stream);
    }

    /// Computes the deterministic Entry ID (Record ID) of the message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn entry_id(&self, author: &str) -> Result<String> {
        #[derive(Serialize)]
        struct EntryId<'a> {
            #[serde(flatten)]
            descriptor: &'a WriteDescriptor,
            author: &'a str,
        }
        cid::from_value(&EntryId {
            descriptor: &self.descriptor,
            author,
        })
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
        let payload: SignaturePayload = serde_json::from_slice(&decoded)?;
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

    async fn verify_integrity(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        if self.is_initial()? {
            if self.descriptor.base.message_timestamp != self.descriptor.date_created {
                return Err(unexpected!("`message_timestamp` and `date_created` do not match"));
            }

            // when the message is a protocol context root, the `context_id`
            // must match the computed `entry_id`
            if self.descriptor.protocol.is_some() && self.descriptor.parent_id.is_none() {
                let author = self.authorization.author()?;
                let context_id = self.entry_id(&author)?;
                if self.context_id != Some(context_id) {
                    return Err(unexpected!("invalid context ID"));
                }
            }
        }

        // verify integrity of messages with protocol
        if self.descriptor.protocol.is_some() {
            integrity::verify(owner, self, provider).await?;

            // FIXME: extract data from stream 1x
            // write record is a grant
            // if self.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
            //     let mut stream =
            //         self.data_stream.clone().ok_or_else(|| unexpected!("missing data stream"))?;
            //     let mut data_bytes = Vec::new();
            //     stream.read_to_end(&mut data_bytes)?;
            //     integrity::verify_schema(self, &data_bytes)?;
            // }
        }

        let decoded = Base64UrlUnpadded::decode_vec(&self.authorization.signature.payload)
            .map_err(|e| unexpected!("issue decoding header: {e}"))?;
        let payload: SignaturePayload = serde_json::from_slice(&decoded)
            .map_err(|e| unexpected!("issue deserializing header: {e}"))?;

        // verify integrity of message against signature payload
        if self.record_id != payload.record_id {
            return Err(unexpected!("message and authorization record IDs do not match"));
        }
        if self.context_id != payload.context_id {
            return Err(unexpected!("message and authorization context IDs do not match"));
        }
        if let Some(attestation_cid) = payload.attestation_cid {
            let expected_cid = cid::from_value(&self.attestation)?;
            if attestation_cid != expected_cid {
                return Err(unexpected!("message and authorization attestation CIDs do not match"));
            }
        }
        if let Some(encryption_cid) = payload.encryption_cid {
            let expected_cid = cid::from_value(&self.encryption)?;
            if encryption_cid != expected_cid {
                return Err(unexpected!("message and authorization `encryptionCid`s do not match"));
            }
        }

        Ok(())
    }

    // Verify immutable properties of two records are identical.
    fn verify_immutable(&self, other: &Self) -> Result<()> {
        let self_desc = &self.descriptor;
        let other_desc = &other.descriptor;

        if self_desc.base.interface != other_desc.base.interface
            || self_desc.base.method != other_desc.base.method
            || self_desc.protocol != other_desc.protocol
            || self_desc.protocol_path != other_desc.protocol_path
            || self_desc.recipient != other_desc.recipient
            || self_desc.schema != other_desc.schema
            || self_desc.parent_id != other_desc.parent_id
            || self_desc.date_created.to_rfc3339_opts(Micros, true)
                != other_desc.date_created.to_rfc3339_opts(Micros, true)
        {
            return Err(unexpected!("immutable properties do not match"));
        }

        Ok(())
    }

    // Determine whether the record is the initial write.
    pub(crate) fn is_initial(&self) -> Result<bool> {
        let entry_id = self.entry_id(&self.authorization.author()?)?;
        Ok(entry_id == self.record_id)
    }

    async fn update_data(
        &mut self, owner: &str, stream: &mut Cursor<Vec<u8>>, store: &impl DataStore,
    ) -> Result<()> {
        // when data is below the threshold, store it within MessageStore
        if self.descriptor.data_size <= data::MAX_ENCODED_SIZE {
            // verify data integrity
            let (data_cid, data_size) = cid::from_reader(stream.clone())?;
            if self.descriptor.data_cid != data_cid {
                return Err(unexpected!("actual data CID does not match message `data_cid`"));
            }
            if self.descriptor.data_size != data_size {
                return Err(unexpected!("actual data size does not match message `data_size`"));
            }

            // store the stream data with the message
            let mut data_bytes = Vec::new();
            stream.read_to_end(&mut data_bytes)?;
            self.encoded_data = Some(Base64UrlUnpadded::encode_string(&data_bytes));

            // write record is a grant
            // TODO: move this check to `verify_integrity` method
            if self.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
                integrity::verify_schema(self, &data_bytes)?;
            }
        } else {
            // store data in DataStore
            let (data_cid, data_size) =
                DataStore::put(store, owner, "<record_id>", &self.descriptor.data_cid, stream)
                    .await?;

            // verify integrity of stored data
            if self.descriptor.data_cid != data_cid {
                return Err(unexpected!("actual data CID does not match message `data_cid`"));
            }
            if self.descriptor.data_size != data_size {
                return Err(unexpected!("actual data size does not match message `data_size`"));
            }
        }

        Ok(())
    }

    // Write message has no data and is not an 'initial write':
    //  1. verify the new message's data integrity
    //  2. copy stored `encoded_data` to the new  message.
    async fn clone_data(
        &mut self, owner: &str, existing: &Entry, store: &impl DataStore,
    ) -> Result<()> {
        let latest = Self::try_from(existing)?;

        // Perform `data_cid` check in case a user attempts to gain access to data
        // by referencing a different known `data_cid`.
        if latest.descriptor.data_cid != self.descriptor.data_cid {
            return Err(unexpected!("data CID does not match descriptor `data_cid`"));
        }
        if latest.descriptor.data_size != self.descriptor.data_size {
            return Err(unexpected!("data size does not match descriptor `data_size`"));
        }

        // if bigger than encoding threshold, ensure data exists for this record
        if latest.descriptor.data_size > data::MAX_ENCODED_SIZE {
            let result =
                DataStore::get(store, owner, "<record_id", &self.descriptor.data_cid).await?;
            if result.is_none() {
                return Err(unexpected!("referenced data does not exist"));
            };
            return Ok(());
        }

        // otherwise, copy `encoded_data` to the new message
        if latest.encoded_data.is_none() {
            return Err(unexpected!("referenced data does not exist"));
        };
        self.encoded_data = latest.encoded_data;

        Ok(())
    }

    // Delete any grant-authorized messages created after grant revocation.
    async fn revoke_grants(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        // verify revocation message matches grant being revoked
        let Some(grant_id) = &self.descriptor.parent_id else {
            return Err(unexpected!("missing `parent_id`"));
        };
        let grant = permissions::fetch_grant(owner, grant_id, provider).await?;

        // verify protocols match
        if let Some(tags) = &self.descriptor.tags {
            let tag_protocol = tags.get("protocol").unwrap_or(&Value::Null);
            if tag_protocol.as_str() != grant.data.scope.protocol() {
                return Err(unexpected!("revocation protocol does not match grant protocol"));
            }
        }

        // find grant-authorized messages with created after revocation
        let query = GrantedQueryBuilder::new()
            .permission_grant_id(grant_id)
            .date_created(DateRange::new().gt(self.descriptor.base.message_timestamp))
            .build();

        let (entries, _) = MessageStore::query(provider, owner, &query).await?;

        // delete the records
        for entry in entries {
            let message_cid = entry.cid()?;
            MessageStore::delete(provider, owner, &message_cid).await?;
            EventLog::delete(provider, owner, &message_cid).await?;
        }

        Ok(())
    }
}

// Signing
impl Write {
    /// Signs the Write message body. The signer is either the author or a delegate.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn sign_as_author(
        &mut self, permission_grant_id: Option<String>, protocol_role: Option<String>,
        signer: &impl Signer,
    ) -> Result<()> {
        let delegated_grant_id = if let Some(grant) = &self.authorization.author_delegated_grant {
            Some(cid::from_value(&grant)?)
        } else {
            None
        };

        // compute CIDs for attestation and encryption
        let attestation_cid = self.attestation.as_ref().map(cid::from_value).transpose()?;
        let encryption_cid = self.encryption.as_ref().map(cid::from_value).transpose()?;

        let payload = SignaturePayload {
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

        self.authorization.signature =
            JwsBuilder::new().payload(payload).add_signer(signer).build().await?;

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
        let owner_jws = JwsBuilder::new().payload(payload).add_signer(signer).build().await?;
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
        let owner_jws = JwsBuilder::new().payload(payload).add_signer(signer).build().await?;

        self.authorization.owner_signature = Some(owner_jws);
        self.authorization.owner_delegated_grant = Some(delegated_grant);

        Ok(())
    }
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignaturePayload {
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

/// Attestation payload.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The attestation's descriptor CID.
    pub descriptor_cid: String,
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

    // TODO: does `tags` need to use Value?
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

// Fetch previous entries for this record, ordered from earliest to latest.
async fn existing_entries(
    owner: &str, record_id: &str, store: &impl MessageStore,
) -> Result<Vec<Entry>> {
    let query = RecordsQueryBuilder::new()
        .add_filter(RecordsFilter::new().record_id(record_id))
        .include_archived(true)
        .method(None)
        .build(); // both Write and Delete messages
    let (entries, _) = store.query(owner, &query).await?;
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
