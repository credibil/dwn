//! # Protocol Integrity

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::permissions::{self, Conditions, Scope, ScopeType};
use crate::protocols::{
    self, Definition, ProtocolType, RuleSet, GRANT_PATH, REQUEST_PATH, REVOCATION_PATH,
};
use crate::provider::MessageStore;
use crate::records::Write;
use crate::store::{ProtocolsQuery, RecordsQuery};
use crate::{forbidden, schema, utils, Range, Result};

/// Type for the data payload of a permission request message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestData {
    /// If the grant is a delegated grant or not. If `true`, `granted_to` will
    /// be able to act as the `granted_by` within the scope of this grant.
    pub delegated: bool,

    /// Optional string that communicates what the grant would be used for.
    pub description: Option<String>,

    /// The scope of the allowed access.
    pub scope: Scope,

    /// Optional conditions that must be met when the grant is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Conditions>,
}

/// Type for the data payload of a permission revocation message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationData {
    /// Optional string that communicates the details of the revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Verify the integrity of `RecordsWrite` messages using a protocol.
pub async fn verify(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let definition = protocol_definition(owner, protocol, store).await?;
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol"));
    };
    let Some(rule_set) = rule_set(protocol_path, &definition.structure) else {
        return Err(forbidden!("no rule set defined for protocol path"));
    };

    verify_type(write, &definition.types)?;
    verify_protocol_path(owner, write, store).await?;
    if rule_set.role.is_some() {
        verify_role_record(owner, write, store).await?;
    }
    verify_size_limit(write.descriptor.data_size, &rule_set)?;
    verify_tags(write.descriptor.tags.as_ref(), &rule_set)?;
    verify_revoke(owner, write, store).await?;

    Ok(())
}

/// Verifies the `data_format` and `schema` parameters .
fn verify_type(write: &Write, types: &BTreeMap<String, ProtocolType>) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').last() else {
        return Err(forbidden!("missing type name"));
    };
    let Some(protocol_type) = types.get(type_name) else {
        return Err(forbidden!("record with type {type_name} not allowed in protocol"));
    };

    if protocol_type.schema.is_some() && protocol_type.schema != write.descriptor.schema {
        return Err(forbidden!("invalid schema for type {type_name}"));
    }

    if let Some(data_formats) = &protocol_type.data_formats {
        if !data_formats.contains(&write.descriptor.data_format) {
            return Err(forbidden!("invalid data_format for type {type_name}"));
        }
    }

    Ok(())
}

// Verifies the given `RecordsWrite` protocol.
pub fn verify_schema(write: &Write, data: &[u8]) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };

    match protocol_path.as_str() {
        REQUEST_PATH => {
            let request_data: RequestData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionRequestData", &request_data)?;
            verify_scope(write, &request_data.scope.scope_type)
        }
        GRANT_PATH => {
            let grant_data: RequestData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionGrantData", &grant_data)?;
            verify_scope(write, &grant_data.scope.scope_type)
        }
        REVOCATION_PATH => {
            let revocation_data: RevocationData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionGrantData", &revocation_data)
        }
        _ => Err(forbidden!("unexpected permission record: {protocol_path}")),
    }
}

/// Validate tags include a protocol tag matching the scoped protocol.
fn verify_scope(write: &Write, scope: &ScopeType) -> Result<()> {
    // validation difficult to do using JSON schema
    let scope_protocol = match scope {
        ScopeType::Records { protocol, .. } => {
            if Some(protocol) != write.descriptor.protocol.as_ref() {
                return Err(forbidden!("scope protocol does not match record protocol",));
            }
            protocol
        }
        _ => return Err(forbidden!("invalid scope type")),
    };

    let Some(tags) = &write.descriptor.tags else {
        return Err(forbidden!("grants require a `tags` property"));
    };
    let Some(tag_protocol) = tags.get("protocol") else {
        return Err(forbidden!("grants must have a `tags` property containing a protocol tag",));
    };
    if tag_protocol != scope_protocol {
        return Err(forbidden!(
            "grants must have a scope with a protocol matching the tagged protocol: {tag_protocol}"
        ));
    }

    Ok(())
}

// Verify the `protocol_path` matches the path of actual record chain.
async fn verify_protocol_path(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').last() else {
        return Err(forbidden!("missing type name"));
    };

    // fetch the parent message
    let Some(parent_id) = &write.descriptor.parent_id else {
        if protocol_path != type_name {
            return Err(forbidden!("invalid protocol path for parentless record",));
        }
        return Ok(());
    };
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(forbidden!("missing protocol"));
    };

    let query = RecordsQuery::new().record_id(parent_id).protocol(protocol).build();
    let (records, _) = store.query(owner, &query).await?;
    if records.is_empty() {
        return Err(forbidden!("unable to find Write Record for parent_id {parent_id}"));
    }

    let Some(parent) = &records[0].as_write() else {
        return Err(forbidden!("expected `RecordsWrite` message"));
    };

    // verify protocol_path is a child of the parent message's protocol_path
    let Some(parent_path) = &parent.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    if &format!("{parent_path}/${type_name}") != protocol_path {
        return Err(forbidden!("invalid `protocol_path`"));
    }

    // verifying context_id is a child of the parent's context_id
    let Some(context_id) = &write.context_id else {
        return Err(forbidden!("missing context_id"));
    };
    let Some(parent_context_id) = &parent.context_id else {
        return Err(forbidden!("missing parent context_id"));
    };
    if context_id != &format!("{parent_context_id}/{}", write.record_id) {
        return Err(forbidden!("invalid `context_id`"));
    }

    Ok(())
}

/// Verify the integrity of the `records::Write` as a role record.
async fn verify_role_record(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(recipient) = &write.descriptor.recipient else {
        return Err(forbidden!("role record is missing recipient"));
    };
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(forbidden!("missing protocol"));
    };
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol_path"));
    };

    // if this is not the root record, add a prefix filter to the query
    let mut query = RecordsQuery::new()
        .protocol(protocol)
        .protocol_path(protocol_path)
        .add_recipient(recipient);

    if let Some(parent_context) =
        write.context_id.as_ref().and_then(|context_id| context_id.rsplit_once('/').map(|x| x.0))
    {
        query = query.context_id(Range::new(
            Some(parent_context.to_string()),
            Some(format!("{parent_context}\u{ffff}")),
        ));
    };

    let (entries, _) = store.query(owner, &query.build()).await?;
    for entry in entries {
        let Some(w) = entry.as_write() else {
            return Err(forbidden!("expected `RecordsWrite` message"));
        };
        if w.record_id != write.record_id {
            return Err(forbidden!("DID '{recipient}' is already recipient of a role record",));
        }
    }

    Ok(())
}

// Verify write record adheres to the $size constraints.
fn verify_size_limit(data_size: usize, rule_set: &RuleSet) -> Result<()> {
    let Some(range) = &rule_set.size else {
        return Ok(());
    };

    if let Some(start) = range.start {
        if data_size < start {
            return Err(forbidden!("data size is less than allowed"));
        }
    }
    if let Some(end) = range.end {
        if data_size > end {
            return Err(forbidden!("data size is greater than allowed"));
        }
    }

    Ok(())
}

fn verify_tags(tags: Option<&Map<String, Value>>, rule_set: &RuleSet) -> Result<()> {
    let Some(rule_set_tags) = &rule_set.tags else {
        return Ok(());
    };

    let additional_properties = rule_set_tags.allow_undefined_tags.unwrap_or_default();
    let required_default = vec![];
    let required = rule_set_tags.required_tags.as_ref().unwrap_or(&required_default);
    let properties = &rule_set_tags.undefined_tags;

    let schema = json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": additional_properties,
    });

    // validate tags against schema
    let instance = serde_json::to_value(tags)?;
    if !jsonschema::is_valid(&schema, &instance) {
        return Err(forbidden!("tags do not match schema"));
    }

    Ok(())
}

// Performs additional validation before storing the RecordsWrite if it is
// a core RecordsWrite that needs additional processing.
async fn verify_revoke(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    // Ensure the protocol tag of a permission revocation RecordsWrite and
    // the parent grant's scoped protocol match.
    if write.descriptor.protocol == Some(protocols::PROTOCOL_URI.to_owned())
        && write.descriptor.protocol_path == Some(protocols::REVOCATION_PATH.to_owned())
    {
        // get grant from revocation message `parent_id`
        let Some(parent_id) = &write.descriptor.parent_id else {
            return Err(forbidden!("missing `parent_id`"));
        };
        let grant = permissions::fetch_grant(owner, parent_id, store).await?;

        // compare revocation message protocol and grant scope protocol
        if let Some(tags) = &write.descriptor.tags {
            let revoke_protocol =
                tags.get("protocol").map_or("", |p| p.as_str().unwrap_or_default());

            let ScopeType::Records { protocol, .. } = grant.data.scope.scope_type else {
                return Err(forbidden!("missing protocol in grant scope"));
            };

            if protocol != revoke_protocol {
                return Err(forbidden!("revocation protocol {revoke_protocol} does not match grant protocol {protocol}"));
            }
        }
    }
    Ok(())
}

// Fetches the protocol definition for the the protocol specified in the message.
pub async fn protocol_definition(
    owner: &str, protocol_uri: &str, store: &impl MessageStore,
) -> Result<Definition> {
    let protocol_uri = utils::clean_url(protocol_uri)?;

    // use default definition if first-class protocol
    if protocol_uri == protocols::PROTOCOL_URI {
        return Ok(Definition::default());
    }

    // fetch the corresponding protocol definition
    let query = ProtocolsQuery::new().protocol(&protocol_uri).build();
    let (protocols, _) = store.query(owner, &query).await?;
    if protocols.is_empty() {
        return Err(forbidden!("unable to find protocol definition for {protocol_uri}"));
    }

    let Some(protocol) = protocols[0].as_configure() else {
        return Err(forbidden!("expected `ProtocolsConfigure` message"));
    };
    Ok(protocol.descriptor.definition.clone())
}

pub fn rule_set(protocol_path: &str, structure: &BTreeMap<String, RuleSet>) -> Option<RuleSet> {
    let Some((type_name, protocol_path)) = protocol_path.split_once('/') else {
        return structure.get(protocol_path).cloned();
    };
    rule_set(protocol_path, &structure.get(type_name)?.structure)
}
