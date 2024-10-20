//! # Authorization

pub mod grant;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use vercre_did::DidResolver;
pub use vercre_did::{dereference, Resource};
use vercre_infosec::Jws;

use crate::{records, Interface, Method};

/// Generate a closure to resolve pub key material required by `Jws::decode`.
///
/// # Example
///
/// ```rust,ignore
/// use vercre_infosec::{verify_key, SecOps};
///
/// let resolver = SecOps::resolver(&provider, &request.credential_issuer)?;
/// let jwt = jws::decode(proof_jwt, verify_key!(resolver)).await?;
/// ...
/// ```
#[doc(hidden)]
// #[macro_export]
macro_rules! verify_key {
    ($resolver:expr) => {{
        // create local reference before moving into closure
        let resolver = $resolver;

        move |kid: String| async move {
            let resp = dereference(&kid, None, resolver).await?;
            let Some(Resource::VerificationMethod(vm)) = resp.content_stream else {
                return Err(anyhow!("Verification method not found"));
            };
            vm.method_type.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
        }
    }};
}

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The signature of the message signer.
    /// N.B.: Not the author of the message when signer is a delegate.
    pub signature: Jws,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// An "overriding" signature for a DWN owner or owner-delegate to store a
    /// message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}

/// Delegated grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedGrant {
    ///The grant's authorization.
    pub authorization: Box<Authorization>,

    /// CID referencing the record associated with the message.
    pub record_id: String,

    /// Context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    pub descriptor: records::WriteDescriptor,

    pub encoded_data: String,
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignaturePayload {
    /// The CID of the message descriptor.
    pub descriptor_cid: String,

    /// The ID of the permission grant for the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,

    /// Record ID of a permission grant DWN `RecordsWrite` with `delegated` set to `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_grant_id: Option<String>,

    /// Used in the Records interface to authorize role-authorized actions for protocol records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_role: Option<String>,
}

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The signature of the message signer.
    /// N.B.: Not the author of the message when signer is a delegate.
    pub signature: Jws,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// An "overriding" signature for a DWN owner or owner-delegate to store a
    /// message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}

impl Authorization {
    /// Verify message signatures.
    pub async fn authenticate(&self, resolver: &impl DidResolver) -> Result<()> {
        let verifier = verify_key!(resolver);
        self.signature.verify(verifier).await?;

        if let Some(signature) = &self.owner_signature {
            signature.verify(verifier).await?;
        }
        if let Some(grant) = &self.author_delegated_grant {
            grant.authorization.signature.verify(verifier).await?;
        }
        if let Some(grant) = &self.owner_delegated_grant {
            grant.authorization.signature.verify(verifier).await?;
        }

        Ok(())
    }

    // TODO: cache this value
    /// Get message author's DID.
    pub fn author(&self) -> Result<String> {
        // author from author delegated grant or signer
        if let Some(grant) = &self.author_delegated_grant {
            signer_did(&grant.authorization.signature)
        } else {
            signer_did(&self.signature)
        }
    }
}

/// Gets the DID of the signer of the given message, returns `undefined` if message is not signed.
fn signer_did(jws: &Jws) -> Result<String> {
    let Some(kid) = jws.signatures[0].protected.kid() else {
        return Err(anyhow!("Invalid `kid`"));
    };
    let Some(did) = kid.split('#').nth(0) else {
        return Err(anyhow!("Invalid DID"));
    };
    Ok(did.to_owned())
}

  
