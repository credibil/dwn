//! # Grant

pub mod grant;

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use self::grant::{Conditions, Grant, GrantData, Scope};
use crate::protocols::Definition;
use crate::provider::{MessageStore, Provider};
use crate::query::{self, Compare, Criterion};
use crate::service::Message;
use crate::{records, utils, Interface};

/// Default protocol for managing web node permission grants.
pub const PROTOCOL: &str = "https://vercre.website/dwn/permissions";

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GrantOptions {
    /// The entity this grant is for.
    granted_to: String,

    /// The datetime this grant is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    date_granted: Option<String>,

    /// The datetime (UTC ISO-8601) this grant will expire.
    pub date_expires: String,

    /// The ID of the permission request.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,

    /// Describes the purpose of the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    /// Whether the grant is delegated.
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated: Option<bool>,

    /// The scope of the grant.
    scope: Scope,

    /// Conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<Conditions>,
}

/// Create a permission grant.
pub(crate) async fn create_grant(
    owner: &str, options: GrantOptions, provider: &impl Provider,
) -> Result<records::Write> {
    if options.scope.interface == Interface::Records && options.scope.protocol.is_none() {
        return Err(anyhow!("`Records` grants must have scope `protocol` property set"));
    }

    let scope = options.scope;
    let tags = if let Some(protocol) = &scope.protocol {
        let protocol = utils::clean_url(protocol)?;
        let mut map = Map::new();
        map.insert("protocol".to_string(), Value::String(protocol));
        Some(map)
    } else {
        None
    };

    let grant_data = GrantData {
        date_expires: options.date_expires,
        request_id: options.request_id,
        description: options.description,
        delegated: options.delegated,
        scope,
        conditions: options.conditions,
    };
    let grant_bytes = serde_json::to_vec(&grant_data)?;

    let options = records::WriteOptions {
        message_timestamp: options.date_granted.clone(),
        date_created: options.date_granted.clone(),
        recipient: Some(options.granted_to.clone()),
        protocol: Some(records::write::Protocol {
            protocol: PROTOCOL.to_string(),
            protocol_path: "grant".to_string(),
        }),
        data_format: "application/json".to_string(),
        data: records::write::Data::Bytes {
            data: grant_bytes.clone(),
        },
        tags,
        ..records::WriteOptions::default()
    };
    let mut write = records::write::create(owner, options, provider).await?;
    write.encoded_data = Some(Base64UrlUnpadded::encode_string(&grant_bytes));

    Ok(write)

    // return {
    //     grant_record: RecordsWrite,
    //     grant_data: PermissionGrantData,
    //     grant_bytes: Uint8Array,
    //     encoded: DataEncodedRecordsWriteMessage,
    // };
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
        date_expires: grant.date_expires,
        delegated: grant.delegated,
        description: grant.description,
        request_id: grant.request_id,
        scope: grant.scope,
        conditions: grant.conditions,
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
    pub definition: Definition,
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
