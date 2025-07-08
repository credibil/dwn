//! # Permissions
//!
//! Permissions are grants of authority or pre-configured access rights
//! (protocols) that can be used by authorized users to interact with a DWN.
//!
//! The [`permissions`] module brings together methods for evaluating
//! incoming messages to determine whether they have sufficient privileges to
//! undertake the message's action(s).

use anyhow::Context;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};

use crate::error::forbidden;
use crate::grants::{Grant, GrantData, Publication, RecordsScope, RequestData, Scope};
use crate::handlers::Result;
use crate::interfaces::Descriptor;
use crate::interfaces::protocols::{GRANT_PATH, PROTOCOL_URI, REQUEST_PATH, REVOCATION_PATH};
use crate::interfaces::records::{Delete, Query, Read, RecordsFilter, Subscribe, Write};
use crate::provider::MessageStore;
use crate::store::RecordsQueryBuilder;

/// Fetches the grant specified by `grant_id`.
pub async fn fetch_grant(owner: &str, grant_id: &str, store: &impl MessageStore) -> Result<Grant> {
    let query =
        RecordsQueryBuilder::new().add_filter(RecordsFilter::new().record_id(grant_id)).build();
    let (documents, _) = store.query(owner, &query).await?;

    let Some(document) = documents.first() else {
        return Err(forbidden!("no grant found"));
    };
    let Some(write) = document.as_write() else {
        return Err(forbidden!("not a valid grant"));
    };

    let desc = &write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(forbidden!("missing grant data"));
    };
    let grant_bytes = Base64UrlUnpadded::decode_vec(grant_enc).context("decoding grant")?;
    let grant: GrantData = serde_json::from_slice(&grant_bytes).context("deserializing grant")?;

    Ok(Grant {
        id: write.record_id.clone(),
        grantor: write.authorization.signer()?,
        grantee: desc.recipient.clone().unwrap_or_default(),
        date_granted: desc.date_created,
        data: grant,
    })
}

/// Get the scope for a permission record. If the record is a revocation, the
/// scope is fetched from the grant that is being revoked.
pub async fn fetch_scope(owner: &str, write: &Write, store: &impl MessageStore) -> Result<Scope> {
    if write.descriptor.protocol.as_deref() != Some(PROTOCOL_URI) {
        return Err(forbidden!("unexpected protocol for permission record"));
    }
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing `protocol_path`"));
    };
    let Some(encoded) = &write.encoded_data else {
        return Err(forbidden!("missing grant data"));
    };
    let raw_bytes = Base64UrlUnpadded::decode_vec(encoded).context("decoding grant")?;

    match protocol_path.as_str() {
        REQUEST_PATH => {
            let data: RequestData =
                serde_json::from_slice(&raw_bytes).context("deserializing grant request")?;
            Ok(data.scope)
        }
        GRANT_PATH => {
            let data: GrantData =
                serde_json::from_slice(&raw_bytes).context("deserializing grant")?;
            Ok(data.scope)
        }
        REVOCATION_PATH => {
            let Some(parent_id) = &write.descriptor.parent_id else {
                return Err(forbidden!("missing parent ID for revocation record"));
            };
            let grant = fetch_grant(owner, parent_id, store).await?;
            Ok(grant.data.scope)
        }

        _ => Err(forbidden!("invalid `protocol_path`")),
    }
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
        if let Some(oldest) = entries.first().cloned()
            && oldest.descriptor().message_timestamp.lt(timestamp)
        {
            return Err(forbidden!("grant has been revoked"));
        }

        Ok(())
    }

    pub(crate) fn verify_scope(&self, write: &Write) -> Result<()> {
        let Scope::Records { protocol, limited_to, .. } = &self.data.scope else {
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
