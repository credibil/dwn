//! # Records Interface
//!
//! The Records interface provides a mechanism to store data using shared
//! schemas.
//!
//! Shared schemas, some of which may be well-known for a given domain, allow
//! DWN-baswed apps and services to share datasets with one another. This leads
//! to improved cross-app experiences for users.

use std::collections::HashMap;
use std::io::Cursor;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use credibil_ecc::Signer;
use credibil_jose::{Jws, JwsBuilder};
use credibil_proof::{Signature, VerifyBy};

use crate::authorization::{self, Authorization, AuthorizationBuilder, JwsPayload};
pub use crate::client::encryption::decrypt;
use crate::hd_key::DerivationScheme;
use crate::interfaces::Descriptor;
pub use crate::interfaces::records::{
    Attestation, DelegatedGrant, DeleteDescriptor, EncryptOptions, Recipient, RecordsFilter,
    SignaturePayload, Sort,
};
use crate::interfaces::records::{
    Delete, EncryptionProperty, Query, QueryDescriptor, Read, ReadDescriptor, Subscribe,
    SubscribeDescriptor, Tag, Write, WriteDescriptor,
};
use crate::store::Pagination;
use crate::utils::cid;
use crate::{Interface, Method, utils};

/// Options to use when creating a permission grant.
pub struct DeleteBuilder<R, S> {
    message_timestamp: DateTime<Utc>,
    record_id: R,
    prune: Option<bool>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    signer: S,
}

/// Builder state is unfiltered.
#[doc(hidden)]
pub struct NoRecordId;
/// Builder state is filtered.
#[doc(hidden)]
pub struct RecordId(String);

impl Default for DeleteBuilder<NoRecordId, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl DeleteBuilder<NoRecordId, Unsigned> {
    /// Returns a new [`DeleteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            record_id: NoRecordId,
            prune: None,
            permission_grant_id: None,
            protocol_role: None,
            signer: Unsigned,
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn record_id(self, record_id: impl Into<String>) -> DeleteBuilder<RecordId, Unsigned> {
        DeleteBuilder {
            record_id: RecordId(record_id.into()),

            message_timestamp: self.message_timestamp,
            prune: self.prune,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            signer: self.signer,
        }
    }
}

impl<R> DeleteBuilder<R, Unsigned> {
    /// Specifies the permission grant ID.
    #[must_use]
    pub const fn prune(mut self, prune: bool) -> Self {
        self.prune = Some(prune);
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }
}

impl DeleteBuilder<RecordId, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signature>(self, signer: &S) -> DeleteBuilder<RecordId, Signed<'_, S>> {
        DeleteBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            record_id: self.record_id,
            prune: self.prune,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
        }
    }
}

impl<S: Signature> DeleteBuilder<RecordId, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue authorizing the message.
    pub async fn build(self) -> Result<Delete> {
        let descriptor = DeleteDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Delete,
                message_timestamp: self.message_timestamp,
            },
            record_id: self.record_id.0,
            prune: self.prune.unwrap_or(false),
        };

        let mut auth_builder =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            auth_builder = auth_builder.permission_grant_id(id);
        }
        if let Some(role) = self.protocol_role {
            auth_builder = auth_builder.protocol_role(role);
        }
        let authorization = auth_builder.build(self.signer.0).await?;

        #[allow(clippy::needless_update)]
        Ok(Delete {
            descriptor,
            authorization,
            ..Delete::default()
        })
    }
}

/// Options to use when creating a permission grant.
pub struct QueryBuilder<F, S> {
    message_timestamp: DateTime<Utc>,
    filter: F,
    date_sort: Option<Sort>,
    pagination: Option<Pagination>,
    protocol_role: Option<String>,
    permission_grant_id: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    signer: S,
}

/// Builder state is unsigned.
#[doc(hidden)]
pub struct Unsigned;
/// Builder state is signed.
#[doc(hidden)]
pub struct Signed<'a, S: Signature>(pub &'a S);

/// Builder state is unfiltered.
#[doc(hidden)]
pub struct Unfiltered;
/// Builder state is filtered.
#[doc(hidden)]
pub struct Filtered(RecordsFilter);

impl Default for QueryBuilder<Unfiltered, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBuilder<Unfiltered, Unsigned> {
    /// Returns a new [`QueryBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            filter: Unfiltered,
            signer: Unsigned,
            date_sort: None,
            pagination: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
        }
    }

    /// Set the filter to use when querying.
    #[must_use]
    pub fn filter(self, filter: RecordsFilter) -> QueryBuilder<Filtered, Unsigned> {
        QueryBuilder {
            filter: Filtered(filter),
            message_timestamp: self.message_timestamp,
            date_sort: self.date_sort,
            pagination: self.pagination,
            signer: self.signer,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
        }
    }
}

/// State: Unsigned
impl<'a, F> QueryBuilder<F, Unsigned> {
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

    /// Determines which date to use when sorting query results.
    #[must_use]
    pub const fn date_sort(mut self, date_sort: Sort) -> Self {
        self.date_sort = Some(date_sort);
        self
    }

    /// Sets the limit (size) and offset of the resultset pagination cursor.
    #[must_use]
    pub fn pagination(mut self, pagination: Pagination) -> Self {
        self.pagination = Some(pagination);
        self
    }

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signature>(self, signer: &'a S) -> QueryBuilder<F, Signed<'a, S>> {
        QueryBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            filter: self.filter,
            date_sort: self.date_sort,
            pagination: self.pagination,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
        }
    }
}

// Build without signing
impl QueryBuilder<Filtered, Unsigned> {
    /// Build the write message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue normalizing filter URLs.
    pub fn build(self) -> Result<Query> {
        Ok(Query {
            descriptor: QueryDescriptor {
                base: Descriptor {
                    interface: Interface::Records,
                    method: Method::Query,
                    message_timestamp: self.message_timestamp,
                },
                filter: self.filter.0.normalize()?,
                date_sort: self.date_sort,
                pagination: self.pagination,
            },
            authorization: None,
        })
    }
}

// Build includes signing
impl<S: Signature> QueryBuilder<Filtered, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue nomalizng filter URLs or
    /// authorizing the message.
    pub async fn build(self) -> Result<Query> {
        let descriptor = QueryDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Query,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0.normalize()?,
            date_sort: self.date_sort,
            pagination: self.pagination,
        };

        let mut auth_builder =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            auth_builder = auth_builder.permission_grant_id(id);
        }
        if let Some(role) = self.protocol_role {
            auth_builder = auth_builder.protocol_role(role);
        }
        if let Some(delegated_grant) = self.delegated_grant {
            auth_builder = auth_builder.delegated_grant(delegated_grant);
        }
        let authorization = Some(auth_builder.build(self.signer.0).await?);

        Ok(Query {
            descriptor,
            authorization,
        })
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct ReadBuilder<F, S> {
    message_timestamp: DateTime<Utc>,
    filter: F,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    signer: S,
}

impl Default for ReadBuilder<Unfiltered, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadBuilder<Unfiltered, Unsigned> {
    /// Returns a new [`ReadBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            filter: Unfiltered,
            permission_grant_id: None,
            protocol_role: None,
            delegated_grant: None,
            signer: Unsigned,
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn filter(self, filter: RecordsFilter) -> ReadBuilder<Filtered, Unsigned> {
        ReadBuilder {
            message_timestamp: self.message_timestamp,
            filter: Filtered(filter),
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            signer: Unsigned,
        }
    }
}

impl<'a, F> ReadBuilder<F, Unsigned> {
    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    // /// Specify a protocol role for the record.
    // #[must_use]
    // pub const fn authorize(mut self, authorize: bool) -> Self {
    //     self.authorize = Some(authorize);
    //     self
    // }

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

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signature>(self, signer: &'a S) -> ReadBuilder<F, Signed<'a, S>> {
        ReadBuilder {
            message_timestamp: self.message_timestamp,
            filter: self.filter,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            signer: Signed(signer),
        }
    }
}

impl ReadBuilder<Filtered, Unsigned> {
    /// Build and return an anonymous (unsigned) Read message.
    #[must_use]
    pub fn build(self) -> Read {
        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0,
        };

        Read {
            descriptor,
            authorization: None,
        }
    }
}

impl<S: Signature> ReadBuilder<Filtered, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue nomalizng filter URLs or
    /// authorizing the message.
    pub async fn build(self) -> Result<Read> {
        let descriptor = ReadDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Read,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0.normalize()?,
        };

        let mut auth_builder =
            AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
        if let Some(id) = self.permission_grant_id {
            auth_builder = auth_builder.permission_grant_id(id);
        }
        if let Some(role) = self.protocol_role {
            auth_builder = auth_builder.protocol_role(role);
        }
        if let Some(delegated_grant) = self.delegated_grant {
            auth_builder = auth_builder.delegated_grant(delegated_grant);
        }

        Ok(Read {
            descriptor,
            authorization: Some(auth_builder.build(self.signer.0).await?),
        })
    }
}

/// Options to use when creating a permission grant.
pub struct SubscribeBuilder<F, S> {
    message_timestamp: DateTime<Utc>,
    filter: F,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    authorize: Option<bool>,
    signer: S,
}

impl Default for SubscribeBuilder<Unfiltered, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscribeBuilder<Unfiltered, Unsigned> {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            filter: Unfiltered,
            permission_grant_id: None,
            protocol_role: None,
            delegated_grant: None,
            authorize: None,
            signer: Unsigned,
        }
    }

    /// Set the filter to use when querying.
    #[must_use]
    pub fn filter(self, filter: RecordsFilter) -> SubscribeBuilder<Filtered, Unsigned> {
        SubscribeBuilder {
            filter: Filtered(filter),
            message_timestamp: self.message_timestamp,
            signer: self.signer,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            authorize: self.authorize,
        }
    }
}

/// State: Unsigned
impl<'a, F> SubscribeBuilder<F, Unsigned> {
    /// Specifies the permission grant ID.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify a protocol role for the record.
    #[must_use]
    pub const fn authorize(mut self, authorize: bool) -> Self {
        self.authorize = Some(authorize);
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

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the
    /// final build step.
    #[must_use]
    pub fn sign<S: Signature>(self, signer: &'a S) -> SubscribeBuilder<F, Signed<'a, S>> {
        SubscribeBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            filter: self.filter,
            permission_grant_id: self.permission_grant_id,
            protocol_role: self.protocol_role,
            delegated_grant: self.delegated_grant,
            authorize: self.authorize,
        }
    }
}

// State: Signer set
impl<S: Signature> SubscribeBuilder<Filtered, Signed<'_, S>> {
    /// Build the write message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue nomalizng filter URLs or
    /// authorizing the message.
    pub async fn build(self) -> Result<Subscribe> {
        let descriptor = SubscribeDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Subscribe,
                message_timestamp: self.message_timestamp,
            },
            filter: self.filter.0.normalize()?,
        };

        let authorization = if self.authorize.unwrap_or(true) {
            let mut auth_builder =
                AuthorizationBuilder::new().descriptor_cid(cid::from_value(&descriptor)?);
            if let Some(id) = self.permission_grant_id {
                auth_builder = auth_builder.permission_grant_id(id);
            }
            if let Some(role) = self.protocol_role {
                auth_builder = auth_builder.protocol_role(role);
            }
            if let Some(delegated_grant) = self.delegated_grant {
                auth_builder = auth_builder.delegated_grant(delegated_grant);
            }
            Some(auth_builder.build(self.signer.0).await?)
        } else {
            None
        };

        Ok(Subscribe {
            descriptor,
            authorization,
        })
    }
}

/// Options for use when creating a new [`Write`] message.
pub struct WriteBuilder<'a, O, A, S> {
    message_timestamp: DateTime<Utc>,
    recipient: Option<String>,
    protocol: Option<ProtocolBuilder<'a>>,
    schema: Option<String>,
    tags: Option<HashMap<String, Tag>>,
    record_id: Option<String>,
    data: Option<Data>,
    data_format: String,
    date_created: DateTime<Utc>,
    published: Option<bool>,
    date_published: Option<DateTime<Utc>>,
    protocol_role: Option<String>,
    permission_grant_id: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    existing: Option<Write>,
    encryption: Option<EncryptionProperty>,
    origin: O,
    attesters: A,
    signer: S,
}

impl Default for WriteBuilder<'_, New, Unattested, Unsigned> {
    fn default() -> Self {
        Self::new()
    }
}

/// The protocol to use for the Write message.
#[derive(Clone, Debug, Default)]
pub struct ProtocolBuilder<'a> {
    /// Storable protocol.
    pub protocol: &'a str,

    /// Protocol path.
    pub protocol_path: &'a str,

    /// Parent context for the protocol.
    pub parent_context_id: Option<String>,
}

/// Storable data can be raw bytes or CID.
pub enum Data {
    /// Data is a `Cursor`.
    Stream(Cursor<Vec<u8>>),

    /// Data is use to calculate CID and size of previously stored data — as
    /// for `Data::Cid`. The data is not added to the Write record's
    /// `data_stream`.
    ///
    /// N.B. This option can only be used when the referenced data has already
    /// been stored by the web node.
    Bytes(Vec<u8>),

    /// A CID (and size) referencing `BlockStore` data from a previous update
    /// to the Write record.
    ///
    /// N.B. This option can only be used when the referenced data has already
    /// been stored by the web node.
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
        Self::Stream(Cursor::default())
    }
}

impl From<Vec<u8>> for Data {
    fn from(data: Vec<u8>) -> Self {
        Self::Stream(Cursor::new(data))
    }
}

// State 'guards' for the WriteBuilder typestate pattern.

/// The WriteBuilder is in a new state.
#[doc(hidden)]
pub struct New;
/// The WriteBuilder is in an 'existing' state.
#[doc(hidden)]
pub struct Existing;

/// The WriteBuilder is in an 'unattested' state.
#[doc(hidden)]
pub struct Unattested;
/// The WriteBuilder is in an 'attested' state.
#[doc(hidden)]
pub struct Attested<'a, A: Signer>(pub &'a [&'a A]);

/// Create a `Write` record from scratch.
impl WriteBuilder<'_, New, Unattested, Unsigned> {
    /// Returns a new [`WriteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();

        Self {
            message_timestamp: now,
            date_created: now,
            data: None,
            data_format: "application/json".to_string(),
            signer: Unsigned,
            attesters: Unattested,
            origin: New,
            recipient: None,
            protocol: None,
            schema: None,
            tags: None,
            record_id: None,
            published: None,
            date_published: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
            existing: None,
            encryption: None,
        }
    }
}

/// Create a [`Write`] record from an existing record.
impl WriteBuilder<'_, Existing, Unattested, Unsigned> {
    /// Returns a new [`WriteBuilder`] based on an existing `Write` record.
    #[must_use]
    pub fn from(existing: Write) -> Self {
        let mut existing = existing;
        existing.data_stream = None;
        existing.encoded_data = None;

        Self {
            message_timestamp: Utc::now(),
            date_created: existing.descriptor.date_created,
            data: None,
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
            published: None,
            date_published: None,
            protocol_role: None,
            permission_grant_id: None,
            delegated_grant: None,
            encryption: None,
        }
    }
}

/// State: New, Unattested, Unencrypted, and Unsigned.
///
/// Immutable properties are able be set.
impl<'a> WriteBuilder<'a, New, Unattested, Unsigned> {
    /// Set a protocol for the record.
    #[must_use]
    pub fn protocol(mut self, protocol: ProtocolBuilder<'a>) -> Self {
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
}

/// State: Unattested, and Unsigned.
///
///  Mutable properties properties are able to be set for both new and existing
/// `Write` records.
impl<O> WriteBuilder<'_, O, Unattested, Unsigned> {
    /// Storable data as a CID or raw bytes.
    #[must_use]
    pub fn data(mut self, data: Data) -> Self {
        self.data = Some(data);
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
    pub fn add_tag(mut self, name: impl Into<String>, tag: impl Into<Tag>) -> Self {
        self.tags.get_or_insert_with(HashMap::new).insert(name.into(), tag.into());
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

    /// The encryption properties for the record.
    #[must_use]
    pub fn encryption(mut self, encryption: EncryptionProperty) -> Self {
        self.encryption = Some(encryption);
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
impl<'a, O, A> WriteBuilder<'a, O, A, Unsigned> {
    /// Logically (from user POV), have an attester sign the record.
    ///
    /// At this point, the builder simply captures the attester for use in the
    /// final build step. Can only be done if the content hasn't been signed
    /// or encrypted.
    #[must_use]
    pub fn attest<S: Signer>(
        self, attesters: &'a [&'a S],
    ) -> WriteBuilder<'a, O, Attested<'a, S>, Unsigned> {
        WriteBuilder {
            attesters: Attested(attesters),
            message_timestamp: self.message_timestamp,
            recipient: self.recipient,
            protocol: self.protocol,
            schema: self.schema,
            tags: self.tags,
            record_id: self.record_id,
            data: self.data,
            data_format: self.data_format,
            date_created: self.date_created,
            published: self.published,
            date_published: self.date_published,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
            encryption: self.encryption,
            existing: self.existing,
            origin: self.origin,
            signer: self.signer,
        }
    }
}

// State: Unsigned
impl<'a, O, A> WriteBuilder<'a, O, A, Unsigned> {
    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the final
    /// build step. Can only be done if the content hasn't been signed yet.
    #[must_use]
    pub fn sign(
        self, signer: &'a impl Signature,
    ) -> WriteBuilder<'a, O, A, Signed<'a, impl Signature>> {
        WriteBuilder {
            signer: Signed(signer),

            message_timestamp: self.message_timestamp,
            recipient: self.recipient,
            protocol: self.protocol,
            schema: self.schema,
            tags: self.tags,
            record_id: self.record_id,
            data: self.data,
            data_format: self.data_format,
            date_created: self.date_created,
            published: self.published,
            date_published: self.date_published,
            protocol_role: self.protocol_role,
            permission_grant_id: self.permission_grant_id,
            delegated_grant: self.delegated_grant,
            encryption: self.encryption,
            existing: self.existing,
            origin: self.origin,
            attesters: self.attesters,
        }
    }
}

// State: Signed.

/// Builder is ready to build once the `sign` step is complete (i.e. the Signer
/// is set).
impl<O, A, S: Signature> WriteBuilder<'_, O, A, Signed<'_, S>> {
    // TODO: break into separate functions
    fn to_write(&self, author_did: &str) -> Result<Write> {
        let mut write = if let Some(write) = &self.existing {
            write.clone()
        } else {
            // set immutable properties
            let mut write = Write {
                descriptor: WriteDescriptor {
                    base: Descriptor {
                        interface: Interface::Records,
                        method: Method::Write,
                        ..Descriptor::default()
                    },
                    date_created: self.date_created,
                    recipient: self.recipient.clone(),
                    ..WriteDescriptor::default()
                },
                ..Write::default()
            };

            if let Some(record_id) = self.record_id.clone() {
                write.record_id = record_id;
            }
            if let Some(settings) = self.protocol.clone() {
                let normalized = utils::uri::clean(settings.protocol)?;
                write.descriptor.protocol = Some(normalized);
                write.descriptor.protocol_path = Some(settings.protocol_path.to_string());

                // parent_id == last segment of  `parent_context_id`
                if let Some(parent_context_id) = &settings.parent_context_id {
                    write.descriptor.parent_id =
                        parent_context_id.split('/').next_back().map(ToString::to_string);
                }
            }
            if let Some(s) = &self.schema {
                write.descriptor.schema = Some(utils::uri::clean(s)?);
            }

            write
        };

        // mutable properties
        write.descriptor.base.message_timestamp = self.message_timestamp;
        write.descriptor.data_format.clone_from(&self.data_format);

        // tags
        if let Some(tags) = self.tags.clone() {
            write.descriptor.tags = Some(tags);
        }

        // published state
        if let Some(published) = self.published {
            write.descriptor.published = Some(published);

            // set/unset `date_published`
            if published {
                write.descriptor.date_published =
                    Some(self.date_published.unwrap_or(self.message_timestamp));
            } else {
                write.descriptor.date_published = None;
            }
        }

        match &self.data {
            Some(Data::Stream(stream)) => {
                let (data_cid, data_size) = cid::from_reader(stream.clone())?;
                write.descriptor.data_cid = data_cid;
                write.descriptor.data_size = data_size;
                write.data_stream = Some(stream.clone());
            }
            Some(Data::Bytes(data)) => {
                // calculate CID and size only — don't add to `data_stream`
                let data_cid = cid::from_value(data)?;
                write.descriptor.data_cid = data_cid;
                write.descriptor.data_size = data.len();
            }
            Some(Data::Cid { data_cid, data_size }) => {
                write.descriptor.data_cid.clone_from(data_cid);
                write.descriptor.data_size = *data_size;
            }
            None => {}
        }

        if let Some(encryption) = &self.encryption {
            for key in &encryption.key_encryption {
                if key.derivation_scheme == DerivationScheme::ProtocolPath
                    && self.protocol.is_none()
                {
                    return Err(anyhow!(
                        "`protocol` must be specified when using `protocols` encryption scheme"
                    ));
                }
                if key.derivation_scheme == DerivationScheme::Schemas && self.schema.is_none() {
                    return Err(anyhow!(
                        "`schema` must be specified when using `schema` encryption scheme"
                    ));
                }
            }

            write.encryption = Some(encryption.clone());
        }

        write.authorization = Authorization {
            author_delegated_grant: self.delegated_grant.clone(),
            ..Authorization::default()
        };

        // compute `record_id` when not provided
        if write.record_id.is_empty() {
            write.record_id = write.entry_id(author_did)?;
        }

        // compute `context_id` if this is a protocol-space record
        if let Some(settings) = &self.protocol {
            if let Some(parent_context_id) = &write.context_id {
                write.context_id = Some(format!("{parent_context_id}/{}", write.record_id));
            } else if let Some(parent_context_id) = &settings.parent_context_id {
                write.context_id = Some(format!("{parent_context_id}/{}", write.record_id));
            } else {
                write.context_id = Some(write.record_id.clone());
            }
        }

        Ok(write)
    }
}

impl<O, A: Signature, S: Signature> WriteBuilder<'_, O, Attested<'_, A>, Signed<'_, S>> {
    async fn attestation(self, descriptor: &WriteDescriptor) -> Result<Jws> {
        let payload = Attestation {
            descriptor_cid: cid::from_value(descriptor)?,
        };
        let Some(attester) = self.attesters.0.first() else {
            return Err(anyhow!("attesters is empty"));
        };
        let key_ref = attester.verification_method().await?.try_into()?;
        JwsBuilder::new().payload(payload).add_signer(*attester).key_ref(&key_ref).build().await
    }
}

/// State: Unattested, Unencrypted, and Signed.
impl<O, S: Signature> WriteBuilder<'_, O, Unattested, Signed<'_, S>> {
    /// Build the `Write` message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue authorizing the message.
    pub async fn build(self) -> Result<Write> {
        let author_did = if let Some(grant) = &self.delegated_grant {
            authorization::kid_did(&grant.authorization.signature)?
        } else {
            let key_ref = self.signer.0.verification_method().await?;
            let VerifyBy::KeyId(kid) = &key_ref else {
                return Err(anyhow!("key reference is not a DID"));
            };
            did_from_kid(kid)?
        };

        let mut write = self.to_write(&author_did)?;
        write.sign_as_author(self.permission_grant_id, self.protocol_role, self.signer.0).await?;
        Ok(write)
    }
}

/// State: Attested, and Signed.
impl<'a, O, A: Signature, S: Signature> WriteBuilder<'a, O, Attested<'a, A>, Signed<'a, S>> {
    /// Build the `Write` message.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue attesting to or
    /// authorizing the message.
    pub async fn build(self) -> Result<Write> {
        let author_did = if let Some(grant) = &self.delegated_grant {
            authorization::kid_did(&grant.authorization.signature)?
        } else {
            let key_ref = self.signer.0.verification_method().await?;
            let VerifyBy::KeyId(kid) = &key_ref else {
                return Err(anyhow!("key reference is not a DID"));
            };
            did_from_kid(kid)?
        };

        let signer = self.signer.0;
        let protocol_role = self.protocol_role.clone();
        let permission_grant_id = self.permission_grant_id.clone();

        let mut write = self.to_write(&author_did)?;
        write.attestation = Some(self.attestation(&write.descriptor).await?);
        write.sign_as_author(permission_grant_id, protocol_role, signer).await?;
        Ok(write)
    }
}

fn did_from_kid(kid: &str) -> Result<String> {
    let parts: Vec<&str> = kid.split('#').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid key ID"));
    }
    Ok(parts[0].to_string())
}

// Signing
impl Write {
    /// Signs the Write message body. The signer is either the author or a delegate.
    ///
    /// # Errors
    ///
    /// This method will fail when there is an issue serializing the message
    /// to CBOR or when there is an issue signing message. The returned
    /// [`crate::Error`] will contain a brief clarifying description of the
    /// error.
    pub async fn sign_as_author(
        &mut self, permission_grant_id: Option<String>, protocol_role: Option<String>,
        signer: &impl Signature,
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

        let key_ref = signer.verification_method().await?.try_into()?;

        self.authorization.signature =
            JwsBuilder::new().payload(payload).add_signer(signer).key_ref(&key_ref).build().await?;

        Ok(())
    }

    /// Signs the [`Write`] message as the DWN owner.
    ///
    /// This is used when the web node owner wants to retain a copy of a message that
    /// the owner did not author.
    /// N.B.: requires the `RecordsWrite` to already have the author's signature.
    ///
    /// # Errors
    ///
    /// This method will fail when the message has not been previously signed
    /// by the author or there is an issue issue signing the message.
    /// The returned [`crate::Error`] will contain a brief clarifying
    /// description of the error.
    pub async fn sign_as_owner(&mut self, signer: &impl Signature) -> Result<()> {
        if self.authorization.author().is_err() {
            return Err(anyhow!("message signature is required in order to sign as owner"));
        }

        let payload = JwsPayload {
            descriptor_cid: cid::from_value(&self.descriptor)?,
            ..JwsPayload::default()
        };
        let key_ref = signer.verification_method().await?.try_into()?;
        let owner_jws =
            JwsBuilder::new().payload(payload).add_signer(signer).key_ref(&key_ref).build().await?;
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
    ///
    /// This method will fail when the message has not been previously signed
    /// by the author or there is an issue issue signing the message.
    /// The returned [`crate::Error`] will contain a brief clarifying
    /// description of the error.
    pub async fn sign_as_delegate(
        &mut self, delegated_grant: DelegatedGrant, signer: &impl Signature,
    ) -> Result<()> {
        if self.authorization.author().is_err() {
            return Err(anyhow!("signature is required in order to sign as owner delegate"));
        }

        //  descriptorCid, delegatedGrantId, permissionGrantId, protocolRole

        let delegated_grant_id = cid::from_value(&delegated_grant)?;
        let descriptor_cid = cid::from_value(&self.descriptor)?;

        let payload = JwsPayload {
            descriptor_cid,
            delegated_grant_id: Some(delegated_grant_id),
            ..JwsPayload::default()
        };
        let key_ref = signer.verification_method().await?.try_into()?;
        let owner_jws =
            JwsBuilder::new().payload(payload).add_signer(signer).key_ref(&key_ref).build().await?;

        self.authorization.owner_signature = Some(owner_jws);
        self.authorization.owner_delegated_grant = Some(delegated_grant);

        Ok(())
    }
}
