//! # Protocol Integrity

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::permissions::{self, GrantData, RequestData, RevocationData, Scope};
use crate::protocols::{
    self, Definition, GRANT_PATH, ProtocolType, REQUEST_PATH, REVOCATION_PATH, RuleSet, query,
};
use crate::provider::MessageStore;
use crate::records::Write;
use crate::store::{RecordsFilter, RecordsQuery};
use crate::{Result, forbidden, schema, unexpected, utils};

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
        return Err(forbidden!("invalid protocol path"));
    };

    check_protocol_path(owner, write, store).await?;
    check_type(write, &definition.types)?;
    if rule_set.role.is_some() {
        check_role_record(owner, write, store).await?;
    }
    check_size_limit(write.descriptor.data_size, &rule_set)?;
    check_tags(write.descriptor.tags.as_ref(), &rule_set)?;
    check_revoke(owner, write, store).await?;

    Ok(())
}

// Verifies the given `RecordsWrite` protocol.
pub fn verify_schema(write: &Write, data: &[u8]) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };

    // TODO: convert xxx_PATH to enum
    match protocol_path.as_str() {
        REQUEST_PATH => {
            let request_data: RequestData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionRequestData", &request_data)?;
            check_scope(write, &request_data.scope)
        }
        GRANT_PATH => {
            let grant_data: GrantData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionGrantData", &grant_data)?;
            check_scope(write, &grant_data.scope)
        }
        REVOCATION_PATH => {
            let revocation_data: RevocationData = serde_json::from_slice(data)?;
            schema::validate_value("PermissionRevocationData", &revocation_data)
        }
        _ => Err(forbidden!("unexpected permission record: {protocol_path}")),
    }
}

/// Verifies the `data_format` and `schema` parameters .
fn check_type(write: &Write, types: &BTreeMap<String, ProtocolType>) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').next_back() else {
        return Err(forbidden!("missing type name"));
    };
    let Some(protocol_type) = types.get(type_name) else {
        return Err(forbidden!("record not allowed in protocol"));
    };

    if protocol_type.schema.is_some() && protocol_type.schema != write.descriptor.schema {
        return Err(forbidden!("invalid schema"));
    }

    if let Some(data_formats) = &protocol_type.data_formats {
        if !data_formats.contains(&write.descriptor.data_format) {
            return Err(forbidden!("invalid data format"));
        }
    }

    Ok(())
}

/// Validate tags include a protocol tag matching the scoped protocol.
fn check_scope(write: &Write, scope: &Scope) -> Result<()> {
    let Some(protocol) = scope.protocol() else {
        return Ok(());
    };

    let Some(tags) = &write.descriptor.tags else {
        return Err(forbidden!("grants require a `tags` property"));
    };
    let Some(tag_protocol) = tags.get("protocol") else {
        return Err(forbidden!("grant tags must contain a \"protocol\" tag",));
    };
    if tag_protocol != protocol {
        return Err(forbidden!("grant scope protocol does not match protocol"));
    }

    Ok(())
}

// Verify the `protocol_path` matches the path of actual record chain.
async fn check_protocol_path(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(forbidden!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').next_back() else {
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

    // fetch the parent record
    let query = RecordsQuery::new()
        .add_filter(RecordsFilter::new().record_id(parent_id).protocol(protocol));
    let records = store.query(owner, &query.into()).await?;
    if records.is_empty() {
        return Err(forbidden!("unable to find parent record"));
    }
    let Some(record) = &records.first() else {
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
    let Some(context_id) = &write.context_id else {
        return Err(forbidden!("missing `context_id`"));
    };
    // compare the parent segment of `context_id` with `parent_context_id`
    if context_id[..parent_context_id.len()] != *parent_context_id {
        return Err(forbidden!("incorrect parent `context_id`"));
    }

    Ok(())
}

/// Verify the integrity of the `records::Write` as a role record.
async fn check_role_record(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(recipient) = &write.descriptor.recipient else {
        return Err(unexpected!("role record is missing recipient"));
    };
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(unexpected!("missing protocol"));
    };
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(unexpected!("missing protocol_path"));
    };

    // if this is not the root record, add a prefix filter to the query
    let mut filter = RecordsFilter::new()
        .protocol(protocol)
        .protocol_path(protocol_path)
        .add_recipient(recipient);

    if let Some(parent_context) =
        write.context_id.as_ref().and_then(|context_id| context_id.rsplit_once('/').map(|x| x.0))
    {
        // FIXME: implement Range query in `store`
        // query = query.context_id(Range::new(
        //     Some(parent_context.to_string()),
        //     Some(format!("{parent_context}\u{ffff}")),
        // ));
        filter = filter.context_id(parent_context);
    };

    let query = RecordsQuery::new().add_filter(filter);
    let entries = store.query(owner, &query.into()).await?;
    for entry in entries {
        let Some(w) = entry.as_write() else {
            return Err(unexpected!("expected `RecordsWrite` message"));
        };
        if w.record_id != write.record_id {
            return Err(unexpected!("recipient already has this role record",));
        }
    }

    Ok(())
}

// Verify write record adheres to the $size constraints.
fn check_size_limit(data_size: usize, rule_set: &RuleSet) -> Result<()> {
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

fn check_tags(tags: Option<&Map<String, Value>>, rule_set: &RuleSet) -> Result<()> {
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
async fn check_revoke(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
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

// Fetches the protocol definition for the the protocol specified in the message.
pub async fn protocol_definition(
    owner: &str, protocol_uri: &str, store: &impl MessageStore,
) -> Result<Definition> {
    let protocol_uri = utils::clean_url(protocol_uri)?;

    // use default definition if first-class protocol
    if protocol_uri == protocols::PROTOCOL_URI {
        return Ok(protocols::DEFINITION.clone());
    }

    let Some(protocols) = query::fetch_config(owner, Some(protocol_uri), store).await? else {
        return Err(forbidden!("unable to find protocol definition"));
    };
    if protocols.is_empty() {
        return Err(forbidden!("unable to find protocol definition"));
    }

    Ok(protocols[0].descriptor.definition.clone())
}

pub fn rule_set(protocol_path: &str, structure: &BTreeMap<String, RuleSet>) -> Option<RuleSet> {
    let Some((type_name, protocol_path)) = protocol_path.split_once('/') else {
        return structure.get(protocol_path).cloned();
    };
    rule_set(protocol_path, &structure.get(type_name)?.structure)
}
