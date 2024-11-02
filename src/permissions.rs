//! # Grant

pub mod grant;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{Conditions, Grant, GrantBuilder, GrantData, Scope};
use crate::protocols::Definition;
use crate::provider::MessageStore;
use crate::service::Message;

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    owner: &str, grant_id: &str, store: &impl MessageStore,
) -> Result<Grant> {
    let sql = format!(
        "
        WHERE recordId = '{grant_id}'
        " // AND isLatestBaseState = true
    );

    // execute query
    let (messages, _) = store.query(owner, &sql).await?;
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
