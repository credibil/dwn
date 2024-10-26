use anyhow::Result;
use vercre_dwn::protocols::{
    Configure, ConfigureBuilder, Definition as ProtocolDefinition, RuleSet, Type,
};
use vercre_dwn::records::Write;
use vercre_infosec::KeyOps;

use crate::keystore::OWNER_DID;
use crate::store::ProviderImpl;

// A logical grouping of user data used to generate test messages.
#[derive(Clone, Debug)]
pub struct Persona {
    pub did: String,
}

impl Persona {
    pub fn new() -> Self {
        // TODO: generate new DID and key pair
        Self {
            did: OWNER_DID.to_string(),
        }
    }
}

#[derive(Default)]
pub struct ConfigureInput {
    pub published: Option<bool>,
    pub author: Option<Persona>,
    pub message_timestamp: Option<String>,
    pub protocol_definition: Option<ProtocolDefinition>,
    pub permission_grant_id: Option<String>,
    pub delegated_grant: Option<Write>,
}

pub struct ConfigureOutput {
    pub author: Persona,
    pub message: Configure,
    pub protocols_configure: Configure,
}

/// Generates a ProtocolsConfigure message for testing.
/// Optional parameters are generated if not given.
/// Implementation currently uses `ProtocolsConfigure.create()`.
pub async fn protocols_configure(input: ConfigureInput) -> Result<ConfigureOutput> {
    let provider = ProviderImpl::new().await?;

    let author = input.author.unwrap_or_else(|| Persona::new());

    // generate protocol types and  definition if not given
    let definition = match input.protocol_definition {
        Some(definition) => definition,
        None => {
            let mut definition = ProtocolDefinition {
                protocol: "somerandomstring".to_string(), // TestDataGenerator.randomString(20),
                published: input.published.unwrap_or_default(),
                ..ProtocolDefinition::default()
            };

            let label = format!("record{}", "somerandomstring"); // + TestDataGenerator.randomString(10);
            definition.types.insert(
                label.clone(),
                Type {
                    schema: Some("test-object".to_string()),
                    data_formats: Some(vec!["text/plain".to_string()]),
                },
            );
            definition.structure.insert(label, RuleSet::default());
            definition
        }
    };

    let mut builder = ConfigureBuilder::new().definition(definition);
    if let Some(delegated_grant) = input.delegated_grant {
        builder = builder.delegated_grant(delegated_grant);
    }
    if let Some(permission_grant_id) = input.permission_grant_id {
        builder = builder.permission_grant_id(permission_grant_id);
    }

    let signer = provider.signer(&author.did)?;
    let configure = builder.build(&signer).await?;

    Ok(ConfigureOutput {
        author: author.clone(),
        message: configure.clone(),
        protocols_configure: configure,
    })
}
