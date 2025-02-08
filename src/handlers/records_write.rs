//! # Records Write
//!
//! The records write endpoint handles `RecordsWrite` messages —
//! requests to write to records to the DWN's [`MessageStore`].

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Cursor, Read};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::format::SecondsFormat::Micros;
use http::StatusCode;
use serde_json::json;

use crate::authorization::Authorization;
use crate::endpoint::{Message, Reply, Status};
use crate::grants::{Grant, GrantData, RequestData, RevocationData, Scope};
use crate::handlers::{protocols_configure, verify_grant, verify_protocol};
use crate::interfaces::protocols::{
    self, GRANT_PATH, PROTOCOL_URI, ProtocolType, REQUEST_PATH, REVOCATION_PATH, RuleSet,
};
use crate::interfaces::records::{
    DelegatedGrant, RecordsFilter, SignaturePayload, Write, WriteReply,
};
use crate::interfaces::{DateRange, Descriptor, MessageType};
use crate::provider::{DataStore, EventLog, EventStream, MessageStore, Provider};
use crate::store::{Entry, GrantedQueryBuilder, RecordsQueryBuilder, data};
use crate::utils::cid;
use crate::{Error, Method, Result, forbidden, schema, unexpected};

/// Handle — or process — a [`Write`] message.
///
/// # Errors
///
/// The endpoint will return an error when message authorization fails or when
/// an issue occurs attempting to save the [`Write`] message or attendant data.
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
    }

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
    entry.add_index("initial", (code == StatusCode::NO_CONTENT).to_string());

    // save the message and log the event
    MessageStore::put(provider, owner, &entry).await?;
    EventLog::append(provider, owner, &entry).await?;
    EventStream::emit(provider, owner, &entry).await?;

    // when this is an update, archive the initial write (and delete its data?)
    if let Some(entry) = initial_entry {
        let initial = Write::try_from(&entry)?;

        // HACK: rebuild entry's indexes
        let mut entry = Entry::from(&initial);
        entry.add_index("initial", true.to_string());

        MessageStore::put(provider, owner, &entry).await?;
        EventLog::append(provider, owner, &entry).await?;

        if !initial.descriptor.data_cid.is_empty() && write.data_stream.is_some() {
            DataStore::delete(provider, owner, &initial.record_id, &initial.descriptor.data_cid)
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
        DataStore::delete(provider, owner, &write.record_id, &write.descriptor.data_cid).await?;
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

impl Message for Write {
    type Reply = WriteReply;

    fn cid(&self) -> Result<String> {
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
        handle(owner, self, provider).await
    }
}

impl TryFrom<Entry> for Write {
    type Error = crate::Error;

    fn try_from(entry: Entry) -> Result<Self> {
        match entry.message {
            MessageType::Write(write) => Ok(write),
            _ => Err(unexpected!("expected `RecordsWrite` message")),
        }
    }
}

impl TryFrom<&Entry> for Write {
    type Error = crate::Error;

    fn try_from(entry: &Entry) -> Result<Self> {
        match &entry.message {
            MessageType::Write(write) => Ok(write.clone()),
            _ => Err(unexpected!("expected `RecordsWrite` message")),
        }
    }
}

impl Write {
    /// Verify the integrity of `RecordsWrite` messages using a protocol.
    ///
    /// # Errors
    ///
    /// Will fail if the message does not pass the integrity checks.
    pub async fn verify(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(forbidden!("missing protocol"));
        };
        let definition = protocols_configure::definition(owner, protocol, store).await?;
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol"));
        };
        let Some(rule_set) = protocols_configure::rule_set(protocol_path, &definition.structure)
        else {
            return Err(forbidden!("invalid protocol path"));
        };

        self.verify_protocol_path(owner, store).await?;
        self.verify_type(&definition.types)?;
        if rule_set.role.is_some() {
            self.verify_role_record(owner, store).await?;
        }
        self.verify_size_limit(&rule_set)?;
        self.verify_tags(&rule_set)?;
        self.verify_revoke(owner, store).await?;

        Ok(())
    }

    /// Verifies the given `RecordsWrite` grant.
    ///
    /// # Errors
    ///
    /// Will fail if the Grant schema is not valid or the scope cannot be
    /// verified.
    pub fn verify_schema(&self, data: &[u8]) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };

        match protocol_path.as_str() {
            REQUEST_PATH => {
                let request_data: RequestData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionRequestData", &request_data)?;
                self.verify_grant_scope(&request_data.scope)
            }
            GRANT_PATH => {
                let grant_data: GrantData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionGrantData", &grant_data)?;
                self.verify_grant_scope(&grant_data.scope)
            }
            REVOCATION_PATH => {
                let revocation_data: RevocationData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionRevocationData", &revocation_data)
            }
            _ => Err(forbidden!("unexpected permission record: {protocol_path}")),
        }
    }

    /// Verifies the `data_format` and `schema` parameters .
    fn verify_type(&self, types: &BTreeMap<String, ProtocolType>) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };
        let Some(type_name) = protocol_path.split('/').next_back() else {
            return Err(forbidden!("missing type name"));
        };
        let Some(protocol_type) = types.get(type_name) else {
            return Err(forbidden!("record not allowed in protocol"));
        };

        if protocol_type.schema.is_some() && protocol_type.schema != self.descriptor.schema {
            return Err(forbidden!("invalid schema"));
        }

        if let Some(data_formats) = &protocol_type.data_formats {
            if !data_formats.contains(&self.descriptor.data_format) {
                return Err(forbidden!("invalid data format"));
            }
        }

        Ok(())
    }

    /// Validate tags include a protocol tag matching the scoped protocol.
    fn verify_grant_scope(&self, scope: &Scope) -> Result<()> {
        let Some(protocol) = scope.protocol() else {
            return Ok(());
        };
        let Some(tags) = &self.descriptor.tags else {
            return Err(forbidden!("grants require a `tags` property"));
        };
        let Some(tag_protocol) = tags.get("protocol") else {
            return Err(forbidden!("grant tags must contain a \"protocol\" tag",));
        };
        if tag_protocol.as_str() != Some(protocol) {
            return Err(forbidden!("grant scope protocol does not match protocol"));
        }
        Ok(())
    }

    // Verify the `protocol_path` matches the path of actual record chain.
    async fn verify_protocol_path(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };
        let Some(type_name) = protocol_path.split('/').next_back() else {
            return Err(forbidden!("missing type name"));
        };

        // fetch the parent message
        let Some(parent_id) = &self.descriptor.parent_id else {
            if protocol_path != type_name {
                return Err(forbidden!("invalid protocol path for parentless record",));
            }
            return Ok(());
        };
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(forbidden!("missing protocol"));
        };

        // fetch the parent record
        let query = RecordsQueryBuilder::new()
            .add_filter(RecordsFilter::new().record_id(parent_id).protocol(protocol))
            .build();
        let (entries, _) = store.query(owner, &query).await?;
        if entries.is_empty() {
            return Err(forbidden!("unable to find parent record"));
        }
        let Some(record) = &entries.first() else {
            return Err(forbidden!("expected to find parent message"));
        };
        let Some(parent) = record.as_write() else {
            return Err(forbidden!("expected parent to be a `RecordsWrite` message"));
        };

        // verify protocol_path is a child of the parent message's protocol_path
        let Some(parent_path) = &parent.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };
        if &format!("{parent_path}/{type_name}") != protocol_path {
            return Err(forbidden!("invalid `protocol_path`"));
        }

        // verifying `context_id` is a child of the parent's `context_id`
        // e.g. 'bafkreicx24'
        let Some(parent_context_id) = &parent.context_id else {
            return Err(forbidden!("missing parent `context_id`"));
        };
        // e.g. 'bafkreicx24/bafkreibejby'
        let Some(context_id) = &self.context_id else {
            return Err(forbidden!("missing `context_id`"));
        };
        // compare the parent segment of `context_id` with `parent_context_id`
        if context_id[..parent_context_id.len()] != *parent_context_id {
            return Err(forbidden!("incorrect parent `context_id`"));
        }

        Ok(())
    }

    /// Verify the integrity of the `records::Write` as a role record.
    async fn verify_role_record(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(recipient) = &self.descriptor.recipient else {
            return Err(unexpected!("role record is missing recipient"));
        };
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(unexpected!("missing protocol"));
        };
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(unexpected!("missing protocol_path"));
        };

        // if this is not the root record, add a prefix filter to the query
        let mut filter = RecordsFilter::new()
            .protocol(protocol)
            .protocol_path(protocol_path)
            .add_recipient(recipient);

        if let Some(parent_context) =
            self.context_id.as_ref().and_then(|id| id.rsplit_once('/').map(|x| x.0))
        {
            filter = filter.context_id(parent_context);
        }

        let query = RecordsQueryBuilder::new().add_filter(filter).build();
        let (entries, _) = store.query(owner, &query).await?;
        for entry in entries {
            let Some(w) = entry.as_write() else {
                return Err(unexpected!("expected `RecordsWrite` message"));
            };
            if w.record_id != self.record_id {
                return Err(unexpected!("recipient already has this role record",));
            }
        }

        Ok(())
    }

    // Verify write record adheres to the $size constraints.
    fn verify_size_limit(&self, rule_set: &RuleSet) -> Result<()> {
        let data_size = self.descriptor.data_size;

        let Some(range) = &rule_set.size else {
            return Ok(());
        };
        if let Some(start) = range.min {
            if data_size < start {
                return Err(forbidden!("data size is less than allowed"));
            }
        }
        if let Some(end) = range.max {
            if data_size > end {
                return Err(forbidden!("data size is greater than allowed"));
            }
        }
        Ok(())
    }

    fn verify_tags(&self, rule_set: &RuleSet) -> Result<()> {
        let Some(rule_tags) = &rule_set.tags else {
            return Ok(());
        };

        // build schema from rule set tags
        let schema = json!({
            "type": "object",
            "properties": rule_tags.undefined,
            "required": rule_tags.required.clone().unwrap_or_default(),
            "additionalProperties": rule_tags.allow_undefined.unwrap_or_default(),
        });

        // validate tags against schema
        if !jsonschema::is_valid(&schema, &serde_json::to_value(&self.descriptor.tags)?) {
            return Err(forbidden!("tags do not match schema"));
        }

        Ok(())
    }

    // Performs additional validation before storing the RecordsWrite if it is
    // a core RecordsWrite that needs additional processing.
    async fn verify_revoke(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        // Ensure the protocol tag of a permission revocation RecordsWrite and
        // the parent grant's scoped protocol match.
        if self.descriptor.protocol == Some(protocols::PROTOCOL_URI.to_owned())
            && self.descriptor.protocol_path == Some(protocols::REVOCATION_PATH.to_owned())
        {
            // get grant from revocation message `parent_id`
            let Some(parent_id) = &self.descriptor.parent_id else {
                return Err(forbidden!("missing `parent_id`"));
            };
            let grant = verify_grant::fetch_grant(owner, parent_id, store).await?;

            // compare revocation message protocol and grant scope protocol
            if let Some(tags) = &self.descriptor.tags {
                let revoke_protocol =
                    tags.get("protocol").map_or("", |p| p.as_str().unwrap_or_default());

                let Some(protocol) = grant.data.scope.protocol() else {
                    return Err(forbidden!("missing protocol in grant scope"));
                };

                if protocol != revoke_protocol {
                    return Err(forbidden!(
                        "revocation protocol {revoke_protocol} does not match grant protocol {protocol}"
                    ));
                }
            }
        }

        Ok(())
    }
}

impl Write {
    /// Build flattened indexes for the write message.
    #[must_use]
    pub(crate) fn build_indexes(&self) -> HashMap<String, String> {
        let mut indexes = HashMap::new();
        let descriptor = &self.descriptor;

        indexes.insert("interface".to_string(), descriptor.base.interface.to_string());
        indexes.insert("method".to_string(), descriptor.base.method.to_string());
        // indexes.insert("initial".to_string(), false.to_string());
        indexes.insert("recordId".to_string(), self.record_id.clone());
        if let Some(context_id) = &self.context_id {
            indexes.insert("contextId".to_string(), context_id.clone());
        }
        indexes.insert(
            "messageTimestamp".to_string(),
            descriptor.base.message_timestamp.to_rfc3339_opts(Micros, true),
        );
        indexes
            .insert("published".to_string(), descriptor.published.unwrap_or_default().to_string());
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
            let attester = attestation.did().unwrap_or_default();
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

    async fn authorize(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let authzn = &self.authorization;
        let record_owner = authzn.owner()?;

        // if owner signature is set, it must be the same as the tenant DID
        if record_owner.as_ref().is_some_and(|ro| ro != owner) {
            return Err(forbidden!("record owner is not web node owner"));
        }

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
        }

        // when author is the owner, we can directly grant access
        if author == owner {
            return Ok(());
        }

        // permission grant
        let decoded = Base64UrlUnpadded::decode_vec(&authzn.signature.payload)?;
        let payload: SignaturePayload = serde_json::from_slice(&decoded)?;
        if let Some(permission_grant_id) = &payload.base.permission_grant_id {
            let grant = verify_grant::fetch_grant(owner, permission_grant_id, store).await?;
            return grant.permit_write(owner, &author, self, store).await;
        }

        // protocol-specific authorization
        if let Some(protocol) = &self.descriptor.protocol {
            let protocol =
                verify_protocol::Authorizer::new(protocol).context_id(self.context_id.as_ref());
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
            self.verify(owner, provider).await?;
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
            if self.descriptor.protocol == Some(PROTOCOL_URI.to_string()) {
                self.verify_schema(&data_bytes)?;
            }
        } else {
            // store data in DataStore
            let (data_cid, data_size) =
                DataStore::put(store, owner, &self.record_id, &self.descriptor.data_cid, stream)
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
                DataStore::get(store, owner, &self.record_id, &self.descriptor.data_cid).await?;
            if result.is_none() {
                return Err(unexpected!("referenced data does not exist"));
            }
            return Ok(());
        }

        // otherwise, copy `encoded_data` to the new message
        if latest.encoded_data.is_none() {
            return Err(unexpected!("referenced data does not exist"));
        }
        self.encoded_data = latest.encoded_data;

        Ok(())
    }

    // Delete any grant-authorized messages created after grant revocation.
    async fn revoke_grants(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        // verify revocation message matches grant being revoked
        let Some(grant_id) = &self.descriptor.parent_id else {
            return Err(unexpected!("missing `parent_id`"));
        };
        let grant = verify_grant::fetch_grant(owner, grant_id, provider).await?;

        // verify protocols match
        if let Some(tags) = &self.descriptor.tags {
            if let Some(tag_protocol) = tags.get("protocol") {
                if tag_protocol.as_str() != grant.data.scope.protocol() {
                    return Err(unexpected!("revocation protocol does not match grant protocol"));
                }
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

impl DelegatedGrant {
    /// Convert [`DelegatedGrant`] to `permissions::Grant`.
    pub(crate) fn to_grant(&self) -> Result<Grant> {
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
