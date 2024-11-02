use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::protocols::{self, Definition, ProtocolType, RuleSet};
use crate::provider::MessageStore;
use crate::records::Write;
use crate::service::Message;
use crate::{utils, Interface, Method};

/// Performs validation on the structure of `RecordsWrite` messages that use a protocol.
pub async fn verify_integrity(owner: &str, write: &Write, store: impl MessageStore) -> Result<()> {
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(anyhow!("missing protocol"));
    };
    let definition = fetch_definition(owner, protocol, &store).await?;

    verify_type(write, &definition.types)?;
    verify_protocol_path(owner, write, &store).await?;

    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol"));
    };
    let Some(rule_set) = rule_set(protocol_path, &definition.structure) else {
        return Err(anyhow!("no rule set defined for protocol path"));
    };
    if rule_set.role.is_some() {
        verify_role_record(owner, write, &store).await?;
    }

    verify_size_limit(write.descriptor.data_size, &rule_set)?;
    verify_tags(write.descriptor.tags.as_ref(), &rule_set)?;

    Ok(())
}

/// Fetches the protocol definition for the the protocol specified in the message.
async fn fetch_definition(
    owner: &str, protocol_uri: &str, store: &impl MessageStore,
) -> Result<Definition> {
    let protocol_uri = utils::clean_url(protocol_uri)?;

    // use default definition if first-class protocol
    if protocol_uri == protocols::PROTOCOL_URI {
        return Ok(Definition::default());
    }

    // fetch the corresponding protocol definition
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND descriptor.definition.protocol = '{protocol_uri}'
        ",
        interface = Interface::Protocols,
        method = Method::Configure,
    );

    let (protocols, _) = store.query(owner, &sql).await?;
    if protocols.is_empty() {
        return Err(anyhow!("unable to find protocol definition for {protocol_uri}"));
    }
    let Message::ProtocolsConfigure(protocol_message) = &protocols[0] else {
        return Err(anyhow!("unexpected message type"));
    };

    Ok(protocol_message.descriptor.definition.clone())
}

/// Verifies the `data_format` and `schema` parameters .
fn verify_type(write: &Write, types: &BTreeMap<String, ProtocolType>) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').last() else {
        return Err(anyhow!("missing type name"));
    };
    let Some(protocol_type) = types.get(type_name) else {
        return Err(anyhow!("record with type {type_name} not allowed in protocol"));
    };

    if protocol_type.schema.is_some() && protocol_type.schema != write.descriptor.schema {
        return Err(anyhow!("invalid schema for type {type_name}"));
    }

    if let Some(data_formats) = &protocol_type.data_formats {
        if !data_formats.contains(&write.descriptor.data_format) {
            return Err(anyhow!("invalid data_format for type {type_name}"));
        }
    }

    Ok(())
}

// Verify the `protocol_path` matches the path of actual record chain.
async fn verify_protocol_path(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').last() else {
        return Err(anyhow!("missing type name"));
    };

    // fetch the parent message
    let Some(parent_id) = &write.descriptor.parent_id else {
        if protocol_path != type_name {
            return Err(anyhow!("invalid protocol path for parentless record"));
        }
        return Ok(());
    };
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(anyhow!("missing protocol"));
    };

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND descriptor.protocol = '{protocol}'
        AND recordId = '{parent_id}'
        ",
        interface = Interface::Records,
        method = Method::Write,
        // AND isLatestBaseState = true
    );

    let (records, _) = store.query(owner, &sql).await?;
    if records.is_empty() {
        return Err(anyhow!("unable to find Write Record for parent_id {parent_id}"));
    }
    let Message::RecordsWrite(parent) = &records[0] else {
        return Err(anyhow!("unexpected message type"));
    };

    // verify protocol_path is a child of the parent message's protocol_path
    let Some(parent_path) = &parent.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol path"));
    };
    if &format!("{parent_path}/${type_name}") != protocol_path {
        return Err(anyhow!("invalid `protocol_path`"));
    }

    // verifying context_id is a child of the parent's context_id
    let Some(context_id) = &write.context_id else {
        return Err(anyhow!("missing context_id"));
    };
    let Some(parent_context_id) = &parent.context_id else {
        return Err(anyhow!("missing parent context_id"));
    };
    if context_id != &format!("{parent_context_id}/{}", write.record_id) {
        return Err(anyhow!("invalid `context_id`"));
    }

    Ok(())
}

fn rule_set(path: &str, structure: &BTreeMap<String, RuleSet>) -> Option<RuleSet> {
    let Some((type_name, path)) = path.split_once('/') else {
        return structure.get(path).cloned();
    };
    rule_set(path, &structure.get(type_name)?.structure)
}

/// Verify the integrity of the `records::Write` as a role record.
async fn verify_role_record(owner: &str, write: &Write, store: &impl MessageStore) -> Result<()> {
    let Some(recipient) = &write.descriptor.recipient else {
        return Err(anyhow!("role record is missing recipient"));
    };
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(anyhow!("missing protocol"));
    };
    let Some(protocol_path) = &write.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol_path"));
    };

    // if this is not the root record, add a prefix filter to the query
    let mut context = String::new();
    if let Some(parent_context) =
        write.context_id.as_ref().and_then(|context_id| context_id.rsplit_once('/').map(|x| x.0))
    {
        context =
            format!("AND contextId BETWEEN '{parent_context}' AND '{parent_context}\u{ffff}'");
    };

    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND descriptor.protocol = '{protocol}'
        AND descriptor.protocolPath = '{protocol_path}'
        AND recipient = '{recipient}'
        {context}
        ",
        interface = Interface::Records,
        method = Method::Write,
        // AND isLatestBaseState = true
    );

    let (records, _) = store.query(owner, &sql).await?;
    // if records.is_empty() {
    //     return Err(anyhow!("unable to find Write Record for parent_id {parent_id}"));
    // }

    for record in records {
        if let Message::RecordsWrite(matched) = record {
            if matched.record_id != write.record_id {
                return Err(anyhow!("DID '{recipient}' is already recipient of a role record"));
            }
        }
    }

    Ok(())
}

// Verify write record adheres to the $size constraints.
fn verify_size_limit(data_size: u64, rule_set: &RuleSet) -> Result<()> {
    let Some(range) = &rule_set.size else {
        return Ok(());
    };

    if let Some(min) = range.min {
        if data_size < min {
            return Err(anyhow!("data size is less than allowed"));
        }
    }
    if let Some(max) = range.max {
        if data_size > max {
            return Err(anyhow!("data size is greater than allowed"));
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

    // for (tag,value) in &tags.undefined_tags {
    //     schema.as_object_mut()
    // }

    // validate tags against schema
    let instance = serde_json::to_value(tags)?;
    if !jsonschema::is_valid(&schema, &instance) {
        return Err(anyhow!("tags do not match schema"));
    }

    Ok(())
}
