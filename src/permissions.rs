//! # Grant

pub mod grant;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub use self::grant::{Conditions, Grant, GrantBuilder, GrantData, Scope, ScopeType};
use crate::protocols::Definition;
use crate::provider::MessageStore;
use crate::records::Write;
use crate::{unexpected, Interface, Method, Result};

/// Fetch the grant specified by `grant_id`.
pub(crate) async fn fetch_grant(
    owner: &str, grant_id: &str, store: &impl MessageStore,
) -> Result<Grant> {
    let sql = format!(
        "
        WHERE descriptor.interface = '{interface}'
        AND descriptor.method = '{method}'
        AND recordId = '{grant_id}'
        ",
        interface = Interface::Records,
        method = Method::Write,
    ); // AND isLatestBaseState = true
    let (messages, _) = store.query::<Write>(owner, &sql).await?;

    let write = &messages[0];
    let desc = &write.descriptor;

    // unpack message payload
    let Some(grant_enc) = &write.encoded_data else {
        return Err(unexpected!("missing grant data"));
    };
    let grant_bytes = Base64UrlUnpadded::decode_vec(grant_enc)?;
    let grant: GrantData = serde_json::from_slice(&grant_bytes)?;

    Ok(Grant {
        id: write.record_id.clone(),
        grantor: write.authorization.signer()?,
        grantee: desc.recipient.clone().unwrap_or_default(),
        date_granted: desc.date_created,
        data: grant,
    })
}

/// Protocol for managing web node permission grants.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Protocol {
    /// The URI of the web node Permissions protocol.
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
