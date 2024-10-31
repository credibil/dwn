use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::protocols::{self, ProtocolDefinition};
use crate::provider::MessageStore;
use crate::query::{Compare, Criterion, Filter};
use crate::records::Write;
use crate::service::Message;
use crate::{Interface, Method};

/// Performs validation on the structure of RecordsWrite messages that use a protocol.
pub async fn verify_integrity(owner: &str, write: &Write, store: impl MessageStore) -> Result<()> {
    // fetch the protocol definition
    let Some(protocol) = &write.descriptor.protocol else {
        return Err(anyhow!("missing protocol"));
    };

    let protocol_definition = fetch_definition(owner, protocol, &store).await?;

    // // verify declared protocol type exists in protocol and that it conforms to type specification
    // ProtocolAuthorization.verifyType(
    //   incomingMessage.message,
    //   protocolDefinition.types
    // );

    // // validate `protocolPath`
    // await ProtocolAuthorization.verifyProtocolPathAndContextId(
    //   tenant,
    //   incomingMessage,
    //   messageStore,
    // );

    // // get the rule set for the inbound message
    // let ruleSet = ProtocolAuthorization.getRuleSet(
    //   incomingMessage.message.descriptor.protocolPath!,
    //   protocolDefinition,
    // );

    // // Validate as a role record if the incoming message is writing a role record
    // await ProtocolAuthorization.verifyAsRoleRecordIfNeeded(
    //   tenant,
    //   incomingMessage,
    //   ruleSet,
    //   messageStore,
    // );

    // // Verify size limit
    // ProtocolAuthorization.verifySizeLimit(incomingMessage, ruleSet);

    // // Verify protocol tags
    // ProtocolAuthorization.verifyTagsIfNeeded(incomingMessage, ruleSet);

    Ok(())
}

/// Fetches the protocol definition for the the protocol specified in the message.
async fn fetch_definition(
    owner: &str, protocol_uri: &str, store: &impl MessageStore,
) -> Result<ProtocolDefinition> {
    // use default definition for if first-class protocol
    if protocol_uri == protocols::PROTOCOL_URI {
        return protocols::definition();
    }

    // fetch the corresponding protocol definition
    let query = Filter {
        criteria: BTreeMap::from([
            (
                "interface".to_string(),
                Criterion::Single(Compare::Equal(Value::String(Interface::Protocols.to_string()))),
            ),
            (
                "method".to_string(),
                Criterion::Single(Compare::Equal(Value::String(Method::Configure.to_string()))),
            ),
            (
                "protocol".to_string(),
                Criterion::Single(Compare::Equal(Value::String(protocol_uri.to_string()))),
            ),
        ]),
    };

    let (protocols, _) = store.query(owner, vec![query], None, None).await?;
    if protocols.is_empty() {
        return Err(anyhow!("unable to find protocol definition for {protocol_uri}"));
    }

    let Message::ProtocolsConfigure(protocol_message) = &protocols[0] else {
        return Err(anyhow!("unexpected message type"));
    };

    Ok(protocol_message.descriptor.definition.clone())
}

use crate::protocols::ProtocolType;

/// Verifies the `data_format` and `schema` parameters .
fn verify_type(write: Write, types: BTreeMap<String, ProtocolType>) -> Result<()> {
    let Some(protocol_path) = write.descriptor.protocol_path else {
        return Err(anyhow!("missing protocol path"));
    };
    let Some(type_name) = protocol_path.split('/').last() else {
        return Err(anyhow!("missing type name"));
    };
    let Some(protocol_type) = types.get(type_name) else {
        return Err(anyhow!("record with type {type_name} not allowed in protocol"));
    };

    // no `schema` specified in protocol definition means that any schema is allowed
    if protocol_type.schema != write.descriptor.schema {
        return Err(anyhow!("invalid schema"));
        // `type '${typeName}' must have schema '${protocolType.schema}', instead has '${schema}'`
    };

    // // no `dataFormats` specified in protocol definition means that all dataFormats are allowed
    // let { dataFormat } = inboundMessage.descriptor;
    // if (protocolType.dataFormats !== undefined && !protocolType.dataFormats.includes(dataFormat)) {
    //   throw new DwnError(
    //     DwnErrorCode.ProtocolAuthorizationIncorrectDataFormat,
    //     `type '${typeName}' must have data format in (${protocolType.dataFormats}), \
    //     instead has '${dataFormat}'`
    //   );
    // }

    Ok(())
}
