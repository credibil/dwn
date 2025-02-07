//! # Protocol Integrity
//!
//! Functionality to verify the integrity of `RecordsWrite` messages using a
//! protocol.

use std::collections::BTreeMap;

use serde_json::json;

use crate::grants::{self, GrantData, RequestData, RevocationData, Scope};
use crate::interfaces::protocols::{ProtocolType, RuleSet};
use crate::interfaces::records::{RecordsFilter, Write};
use crate::protocols::{self, GRANT_PATH, REQUEST_PATH, REVOCATION_PATH};
use crate::provider::MessageStore;
use crate::store::RecordsQueryBuilder;
use crate::{Result, forbidden, schema, unexpected};

impl Write {
    /// Verify the integrity of `RecordsWrite` messages using a protocol.
    ///
    /// # Errors
    ///
    /// Will fail if the message does not pass the integrity checks.
    pub async fn verify(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(forbidden!("missing protocol"));
        };
        let definition = protocols::definition(owner, protocol, store).await?;
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol"));
        };
        let Some(rule_set) = protocols::rule_set(protocol_path, &definition.structure) else {
            return Err(forbidden!("invalid protocol path"));
        };

        self.verify_protocol_path(owner, store).await?;
        self.verify_type(&definition.types)?;
        if rule_set.role.is_some() {
            self.verify_role_record(owner, store).await?;
        }
        self.verify_size_limit(&rule_set)?;
        self.verify_tags(&rule_set)?;
        self.verify_revoke(owner, store).await?;

        Ok(())
    }

    /// Verifies the given `RecordsWrite` grant.
    ///
    /// # Errors
    ///
    /// Will fail if the Grant schema is not valid or the scope cannot be
    /// verified.
    pub fn verify_schema(&self, data: &[u8]) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };

        match protocol_path.as_str() {
            REQUEST_PATH => {
                let request_data: RequestData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionRequestData", &request_data)?;
                self.verify_grant_scope(&request_data.scope)
            }
            GRANT_PATH => {
                let grant_data: GrantData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionGrantData", &grant_data)?;
                self.verify_grant_scope(&grant_data.scope)
            }
            REVOCATION_PATH => {
                let revocation_data: RevocationData = serde_json::from_slice(data)?;
                schema::validate_value("PermissionRevocationData", &revocation_data)
            }
            _ => Err(forbidden!("unexpected permission record: {protocol_path}")),
        }
    }

    /// Verifies the `data_format` and `schema` parameters .
    fn verify_type(&self, types: &BTreeMap<String, ProtocolType>) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };
        let Some(type_name) = protocol_path.split('/').next_back() else {
            return Err(forbidden!("missing type name"));
        };
        let Some(protocol_type) = types.get(type_name) else {
            return Err(forbidden!("record not allowed in protocol"));
        };

        if protocol_type.schema.is_some() && protocol_type.schema != self.descriptor.schema {
            return Err(forbidden!("invalid schema"));
        }

        if let Some(data_formats) = &protocol_type.data_formats {
            if !data_formats.contains(&self.descriptor.data_format) {
                return Err(forbidden!("invalid data format"));
            }
        }

        Ok(())
    }

    /// Validate tags include a protocol tag matching the scoped protocol.
    fn verify_grant_scope(&self, scope: &Scope) -> Result<()> {
        let Some(protocol) = scope.protocol() else {
            return Ok(());
        };
        let Some(tags) = &self.descriptor.tags else {
            return Err(forbidden!("grants require a `tags` property"));
        };
        let Some(tag_protocol) = tags.get("protocol") else {
            return Err(forbidden!("grant tags must contain a \"protocol\" tag",));
        };
        if tag_protocol.as_str() != Some(protocol) {
            return Err(forbidden!("grant scope protocol does not match protocol"));
        }
        Ok(())
    }

    // Verify the `protocol_path` matches the path of actual record chain.
    async fn verify_protocol_path(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(forbidden!("missing protocol path"));
        };
        let Some(type_name) = protocol_path.split('/').next_back() else {
            return Err(forbidden!("missing type name"));
        };

        // fetch the parent message
        let Some(parent_id) = &self.descriptor.parent_id else {
            if protocol_path != type_name {
                return Err(forbidden!("invalid protocol path for parentless record",));
            }
            return Ok(());
        };
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(forbidden!("missing protocol"));
        };

        // fetch the parent record
        let query = RecordsQueryBuilder::new()
            .add_filter(RecordsFilter::new().record_id(parent_id).protocol(protocol))
            .build();
        let (entries, _) = store.query(owner, &query).await?;
        if entries.is_empty() {
            return Err(forbidden!("unable to find parent record"));
        }
        let Some(record) = &entries.first() else {
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
        let Some(context_id) = &self.context_id else {
            return Err(forbidden!("missing `context_id`"));
        };
        // compare the parent segment of `context_id` with `parent_context_id`
        if context_id[..parent_context_id.len()] != *parent_context_id {
            return Err(forbidden!("incorrect parent `context_id`"));
        }

        Ok(())
    }

    /// Verify the integrity of the `records::Write` as a role record.
    async fn verify_role_record(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        let Some(recipient) = &self.descriptor.recipient else {
            return Err(unexpected!("role record is missing recipient"));
        };
        let Some(protocol) = &self.descriptor.protocol else {
            return Err(unexpected!("missing protocol"));
        };
        let Some(protocol_path) = &self.descriptor.protocol_path else {
            return Err(unexpected!("missing protocol_path"));
        };

        // if this is not the root record, add a prefix filter to the query
        let mut filter = RecordsFilter::new()
            .protocol(protocol)
            .protocol_path(protocol_path)
            .add_recipient(recipient);

        if let Some(parent_context) =
            self.context_id.as_ref().and_then(|id| id.rsplit_once('/').map(|x| x.0))
        {
            filter = filter.context_id(parent_context);
        }

        let query = RecordsQueryBuilder::new().add_filter(filter).build();
        let (entries, _) = store.query(owner, &query).await?;
        for entry in entries {
            let Some(w) = entry.as_write() else {
                return Err(unexpected!("expected `RecordsWrite` message"));
            };
            if w.record_id != self.record_id {
                return Err(unexpected!("recipient already has this role record",));
            }
        }

        Ok(())
    }

    // Verify write record adheres to the $size constraints.
    fn verify_size_limit(&self, rule_set: &RuleSet) -> Result<()> {
        let data_size = self.descriptor.data_size;

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

    fn verify_tags(&self, rule_set: &RuleSet) -> Result<()> {
        let Some(rule_tags) = &rule_set.tags else {
            return Ok(());
        };

        // build schema from rule set tags
        let schema = json!({
            "type": "object",
            "properties": rule_tags.undefined,
            "required": rule_tags.required.clone().unwrap_or_default(),
            "additionalProperties": rule_tags.allow_undefined.unwrap_or_default(),
        });

        // validate tags against schema
        if !jsonschema::is_valid(&schema, &serde_json::to_value(&self.descriptor.tags)?) {
            return Err(forbidden!("tags do not match schema"));
        }

        Ok(())
    }

    // Performs additional validation before storing the RecordsWrite if it is
    // a core RecordsWrite that needs additional processing.
    async fn verify_revoke(&self, owner: &str, store: &impl MessageStore) -> Result<()> {
        // Ensure the protocol tag of a permission revocation RecordsWrite and
        // the parent grant's scoped protocol match.
        if self.descriptor.protocol == Some(protocols::PROTOCOL_URI.to_owned())
            && self.descriptor.protocol_path == Some(protocols::REVOCATION_PATH.to_owned())
        {
            // get grant from revocation message `parent_id`
            let Some(parent_id) = &self.descriptor.parent_id else {
                return Err(forbidden!("missing `parent_id`"));
            };
            let grant = grants::fetch_grant(owner, parent_id, store).await?;

            // compare revocation message protocol and grant scope protocol
            if let Some(tags) = &self.descriptor.tags {
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
}
