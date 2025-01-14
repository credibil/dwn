//! # Records Query

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

use crate::authorization::AuthorizationBuilder;
use crate::data::cid;
use crate::provider::Signer;
use crate::records::{Delete, DeleteDescriptor};
use crate::{Descriptor, Interface, Method};

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct DeleteBuilder {
    message_timestamp: DateTime<Utc>,
    record_id: Option<String>,
    prune: Option<bool>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
}

impl DeleteBuilder {
    /// Returns a new [`DeleteBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_timestamp: Utc::now(),
            ..Self::default()
        }
    }

    /// Specifies the permission grant ID.
    #[must_use]
    pub fn record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

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

    /// Build the write message.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Delete> {
        let Some(record_id) = self.record_id else {
            return Err(anyhow!("`record_id` is not set"));
        };

        let descriptor = DeleteDescriptor {
            base: Descriptor {
                interface: Interface::Records,
                method: Method::Delete,
                message_timestamp: self.message_timestamp,
            },
            record_id,
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
        let authorization = auth_builder.build(signer).await?;

        Ok(Delete {
            descriptor,
            authorization,
        })
    }
}
