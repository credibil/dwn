//! # Permissions Grant
//!
//! The [`grant`] module handles verification of previously issued permission
//! grants.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{RecordsScope, Scope};
use crate::protocols::REVOCATION_PATH;
use crate::provider::MessageStore;
use crate::records::{DelegatedGrant, Delete, Query, Read, RecordsFilter, Subscribe, Write};
use crate::serde::rfc3339_micros;
use crate::store::RecordsQueryBuilder;
use crate::{Descriptor, Result, forbidden, unexpected};

/// [`Grant`] holds permission grant information during the process of
/// verifying an incoming message's authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    /// The ID of the permission grant — the record ID message.
    pub id: String,

    /// The grantor of the permission.
    pub grantor: String,

    /// The grantee of the permission.
    pub grantee: String,

    /// The date at which the grant was given.
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_granted: DateTime<Utc>,

    /// The grant's descriptor.
    #[serde(flatten)]
    pub data: GrantData,
}

impl TryFrom<&Write> for Grant {
    type Error = crate::Error;

    fn try_from(write: &Write) -> Result<Self> {
        let permission_grant = write.encoded_data.clone().unwrap_or_default();
        let grant_data = serde_json::from_str(&permission_grant)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        Ok(Self {
            id: write.record_id.clone(),
            grantor: write.authorization.signer().unwrap_or_default(),
            grantee: write.descriptor.recipient.clone().unwrap_or_default(),
            date_granted: write.descriptor.date_created,
            data: grant_data,
        })
    }
}

impl TryFrom<&DelegatedGrant> for Grant {
    type Error = crate::Error;

    fn try_from(delegated: &DelegatedGrant) -> Result<Self> {
        let bytes = Base64UrlUnpadded::decode_vec(&delegated.encoded_data)?;
        let grant_data = serde_json::from_slice(&bytes)
            .map_err(|e| unexpected!("issue deserializing grant: {e}"))?;

        Ok(Self {
            id: delegated.record_id.clone(),
            grantor: delegated.authorization.signer()?,
            grantee: delegated.descriptor.recipient.clone().unwrap_or_default(),
            date_granted: delegated.descriptor.date_created,
            data: grant_data,
        })
    }
}

/// The [`GrantData`] data structure holds information related to a permission
/// grant.
///
/// The grant is issued as a [`Write`] message with the base64 URL-encoded
/// [`GrantData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantData {
    /// Describes the intended grant use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The CID of permission request. This is optional as grants may be issued
    /// without being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// The date-time when grant expires.
    #[serde(serialize_with = "rfc3339_micros")]
    pub date_expires: DateTime<Utc>,

    /// Specifies whether grant is delegated or not. When set to `true`, the
    /// `granted_to` property acts as the `granted_to` within the scope of the
    /// grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,

    /// The scope of access permitted by the grant.
    pub scope: Scope,

    /// Specifies an conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// [`Conditions`] contains conditions set on the parent `Grant`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conditions {
    /// Indicates whether a message written with the invocation of a permission
    /// must, may, or must not be marked as public. If unset, it is optional to
    /// make the message public.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication: Option<Publication>,
}

/// Condition for publication of a message.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Publication {
    /// The message must be marked as public.
    #[default]
    Required,

    /// The message may be marked as public.
    Prohibited,
}

/// The [`RequestData`] data structure holds information related to a permission
/// grant request.
///
/// The request is made using a [`Write`] message with the base64 URL-encoded
/// [`RequestData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RequestData {
    /// If the grant is a delegated grant or not. If `true`, `granted_to` will
    /// be able to act as the `granted_by` within the scope of this grant.
    pub delegated: bool,

    /// Optional string that communicates what the grant would be used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// The [`RevocationData`] data structure holds information related to a permission
/// grant revocation.
///
/// The revocation is saved as a [`Write`] message with the base64 URL-encoded
/// [`RevocationData`] structure in the `encoded_data` field.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationData {
    /// Optional string that communicates the details of the revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Grant {
    /// Verify the `grantee` is sufficiently authorized to undertake the
    /// action reference by the [`Descriptor`].
    ///
    /// Does not validate grant `conditions` or `scope` beyond `interface` and
    /// `method`.
    pub(crate) async fn verify(
        &self, grantor: &str, grantee: &str, descriptor: &Descriptor, store: &impl MessageStore,
    ) -> Result<()> {
        // verify the `grantee` against intended recipient
        if grantee != self.grantee {
            return Err(forbidden!("grant not granted to grantee"));
        }

        // verifies `grantor` against actual signer
        if grantor != self.grantor {
            return Err(forbidden!("grant not granted by grantor"));
        }

        // verify grant scope for interface
        if descriptor.interface != self.data.scope.interface() {
            return Err(forbidden!("interface is not within grant scope"));
        }

        // verify grant scope method
        if descriptor.method != self.data.scope.method() {
            return Err(forbidden!("method is not within grant scope"));
        }

        // verify the message is within the grant's time frame
        self.is_current(grantor, &descriptor.message_timestamp, store).await?;

        Ok(())
    }

    /// Verify the grant allows the `records::Write` message to be written.
    pub(crate) async fn permit_write(
        &self, grantor: &str, grantee: &str, write: &Write, store: &impl MessageStore,
    ) -> Result<()> {
        self.verify(grantor, grantee, &write.descriptor.base, store).await?;
        self.verify_scope(write)?;
        self.verify_conditions(write)?;
        Ok(())
    }

    /// Verify the grant allows the requestor to access `records::Query` and
    /// `records::Subscribe` records.
    pub(crate) async fn permit_read(
        &self, grantor: &str, grantee: &str, read: &Read, write: &Write, store: &impl MessageStore,
    ) -> Result<()> {
        self.verify(grantor, grantee, &read.descriptor.base, store).await?;
        self.verify_scope(write)?;
        Ok(())
    }

    /// Verify the grant allows the requestor to access `records::Query` and
    /// `records::Subscribe` records.
    pub(crate) async fn permit_query(
        &self, grantor: &str, grantee: &str, query: &Query, store: &impl MessageStore,
    ) -> Result<()> {
        let descriptor = &query.descriptor;

        self.verify(grantor, grantee, &descriptor.base, store).await?;

        // verify protocols match
        if self.data.scope.protocol().is_none() {
            return Ok(());
        }
        if descriptor.filter.protocol.as_deref() != self.data.scope.protocol() {
            return Err(forbidden!("grant and query protocols do not match",));
        }

        Ok(())
    }

    /// Verify the grant allows the requestor to access `records::Query` and
    /// `records::Subscribe` records.
    pub(crate) async fn permit_subscribe(
        &self, grantor: &str, grantee: &str, subscribe: &Subscribe, store: &impl MessageStore,
    ) -> Result<()> {
        let descriptor = &subscribe.descriptor;

        self.verify(grantor, grantee, &descriptor.base, store).await?;

        // verify protocols match
        if self.data.scope.protocol().is_none() {
            return Ok(());
        }
        if descriptor.filter.protocol.as_deref() != self.data.scope.protocol() {
            return Err(forbidden!("grant protocol does not match query protocol",));
        }

        Ok(())
    }

    /// Verify the grant allows the `records::Write` message to be deleted.
    pub(crate) async fn permit_delete(
        &self, grantor: &str, grantee: &str, delete: &Delete, write: &Write,
        store: &impl MessageStore,
    ) -> Result<()> {
        self.verify(grantor, grantee, &delete.descriptor.base, store).await?;

        // must be deleting a record with the same protocol
        if self.data.scope.protocol().is_none() {
            return Ok(());
        }
        if write.descriptor.protocol.as_deref() != self.data.scope.protocol() {
            return Err(forbidden!("grant protocol does not match delete protocol",));
        }

        Ok(())
    }

    /// Verify that the message is within the allowed time frame of the grant, and
    /// the grant has not been revoked.
    async fn is_current(
        &self, grantor: &str, timestamp: &DateTime<Utc>, store: &impl MessageStore,
    ) -> Result<()> {
        // Check that message is within the grant's time frame
        if timestamp.lt(&self.date_granted) {
            return Err(forbidden!("grant is not yet active"));
        }
        if timestamp.ge(&self.data.date_expires) {
            return Err(forbidden!("grant has expired"));
        }

        // check if grant has been revoked — using latest revocation message
        let query = RecordsQueryBuilder::new()
            .add_filter(RecordsFilter::new().parent_id(&self.id).protocol_path(REVOCATION_PATH))
            .build();

        let (entries, _) = store.query(grantor, &query).await?;
        if let Some(oldest) = entries.first().cloned() {
            if oldest.descriptor().message_timestamp.lt(timestamp) {
                return Err(forbidden!("grant has been revoked"));
            }
        }

        Ok(())
    }

    pub(crate) fn verify_scope(&self, write: &Write) -> Result<()> {
        let Scope::Records {
            protocol, limited_to, ..
        } = &self.data.scope
        else {
            return Err(forbidden!("invalid scope: `Records` scope must have protocol set"));
        };

        if Some(protocol) != write.descriptor.protocol.as_ref() {
            return Err(forbidden!("scope protocol does not match write protocol"));
        }

        match limited_to {
            Some(RecordsScope::ContextId(grant_context_id)) => {
                let Some(write_context_id) = &write.context_id else {
                    return Err(forbidden!("missing `context_id`"));
                };
                if !write_context_id.starts_with(grant_context_id) {
                    return Err(forbidden!("record not part of grant context"));
                }
            }
            Some(RecordsScope::ProtocolPath(protocol_path)) => {
                if Some(protocol_path) != write.descriptor.protocol_path.as_ref() {
                    return Err(forbidden!("grant and record protocol paths do not match"));
                }
            }
            None => {}
        }

        Ok(())
    }

    fn verify_conditions(&self, write: &Write) -> Result<()> {
        let Some(conditions) = &self.data.conditions else {
            return Ok(());
        };

        match conditions.publication {
            Some(Publication::Required) => {
                if !write.descriptor.published.unwrap_or_default() {
                    return Err(forbidden!("grant requires message to be published",));
                }
            }
            Some(Publication::Prohibited) => {
                if write.descriptor.published.unwrap_or_default() {
                    return Err(forbidden!("grant prohibits publishing message"));
                }
            }
            None => {}
        }

        Ok(())
    }
}
