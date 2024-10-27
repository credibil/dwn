//! # Grant

pub mod grant;

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::grant::{Conditions, Grant, GrantData, Scope};
use crate::protocols::ProtocolDefinition;
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::records::{self, write};
use crate::service::Message;
use crate::{utils, Interface, Method};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL: &str = "https://vercre.website/dwn/permissions";

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct GrantBuilder {
    owner: String,
    issued_to: String,
    date_expires: String,
    request_id: Option<String>,
    description: Option<String>,
    delegated: Option<bool>,
    scope: Option<Scope>,
    conditions: Option<Conditions>,
}

/// Builder for creating a permission grant.
impl GrantBuilder {
    /// Returns a new [`GrantBuilder`]
    #[must_use]
    pub fn new(owner: String) -> Self {
        // set defaults
        Self {
            owner,
            date_expires: (Utc::now() + Duration::seconds(100)).to_rfc3339(),
            ..Self::default()
        }
    }

    /// Specify who the grant is issued to.
    #[must_use]
    pub fn issued_to(mut self, issued_to: String) -> Self {
        self.issued_to = issued_to;
        self
    }

    /// The time in seconds after which the issued grant will expire. Defaults
    /// to 100 seconds.
    #[must_use]
    pub fn expires_in(mut self, seconds: i64) -> Self {
        if seconds <= 0 {
            return self;
        }
        self.date_expires = (Utc::now() + Duration::seconds(seconds)).to_rfc3339();
        self
    }

    /// Specify an ID to use for the permission request.
    #[must_use]
    pub fn request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Describe the purpose of the grant.
    #[must_use]
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Specify whether the grant is delegated or not.
    #[must_use]
    pub const fn delegated(mut self, delegated: bool) -> Self {
        self.delegated = Some(delegated);
        self
    }

    /// Specify the scope of the grant.
    #[must_use]
    pub fn scope(mut self, interface: Interface, method: Method, protocol: Option<String>) -> Self {
        self.scope = Some(Scope {
            interface,
            method,
            protocol,
        });
        self
    }

    /// Specify conditions that must be met when the grant is used.
    #[must_use]
    pub const fn conditions(mut self, conditions: Conditions) -> Self {
        self.conditions = Some(conditions);
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, provider: &impl Provider) -> Result<records::Write> {
        if self.issued_to.is_empty() {
            return Err(anyhow!("missing `issued_to`"));
        }
        let Some(scope) = self.scope else {
            return Err(anyhow!("missing `scope`"));
        };

        let grant_bytes = serde_json::to_vec(&GrantData {
            date_expires: self.date_expires,
            request_id: self.request_id,
            description: self.description,
            delegated: self.delegated,
            scope: scope.clone(),
            conditions: self.conditions,
        })?;

        let mut builder = write::WriteBuilder::new(&self.owner)
            .recipient(self.issued_to)
            .protocol(write::Protocol {
                protocol: PROTOCOL.to_string(),
                protocol_path: "grant".to_string(),
            })
            .data(write::Data::Bytes {
                data: grant_bytes.clone(),
            });

        if let Some(protocol) = &scope.protocol {
            let protocol = utils::clean_url(protocol)?;
            builder = builder.add_tag("protocol".to_string(), Value::String(protocol));
        };

        let mut write = builder.build(provider).await?;
        write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

        Ok(write)

        // Ok(Grant {
        //     grant_record: RecordsWrite,
        //     grant_data: PermissionGrantData,
        //     grant_bytes: Uint8Array,
        //     encoded: DataEncodedRecordsWriteMessage,
        // })
    }
}

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    owner: &str, grant_id: &str, provider: &impl Provider,
) -> Result<Grant> {
    let mut qf = query::Filter {
        criteria: BTreeMap::<String, Criterion>::new(),
    };
    qf.criteria.insert(
        "recordId".to_string(),
        Criterion::Single(Compare::Equal(Value::String(grant_id.to_owned()))),
    );
    qf.criteria.insert(
        "isLatestBaseState".to_string(),
        Criterion::Single(Compare::Equal(Value::Bool(true))),
    );

    // execute query
    let (messages, _) = MessageStore::query(provider, owner, vec![qf], None, None).await?;
    let message = &messages[0];
    let Message::RecordsWrite(write) = message.clone() else {
        return Err(anyhow!("no grant matching {grant_id}"));
    };
    let desc = write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(anyhow!("missing grant data"));
    };
    let grant_bytes = Base64UrlUnpadded::decode_vec(grant_enc)?;
    let grant: GrantData = serde_json::from_slice(&grant_bytes)?;

    Ok(Grant {
        id: write.record_id,
        grantor: message.signer().unwrap_or_default(),
        grantee: desc.recipient.unwrap_or_default(),
        date_granted: desc.date_created,
        data: grant,
    })
}

/// Protocol for managing web node permission grants.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Protocol {
    /// The URI of the DWN Permissions protocol.
    pub uri: String,

    /// The protocol path of the `request` record.
    pub request_path: String,

    /// The protocol path of the `grant` record.
    pub grant_path: String,

    /// The protocol path of the `revocation` record.
    pub revocation_path: String,

    /// Permissions protocol definition.
    pub definition: ProtocolDefinition,
}

#[cfg(test)]
mod tests {

    // use super::*;

    #[test]
    fn url() {
        let url = url::Url::parse("http://test.com/test#test").unwrap();

        println!("{}", url.origin().ascii_serialization() + url.path())
    }
}
