//! # Authorization

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use vercre_did::DidResolver;
pub use vercre_did::{Resource, dereference};
use vercre_infosec::jose::JwsBuilder;
use vercre_infosec::{Jws, Signer};

use crate::data::cid;
use crate::records::DelegatedGrant;
use crate::{Result, unexpected};

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
macro_rules! verify_key {
    ($resolver:expr) => {{
        // create local reference before moving into closure
        let resolver = $resolver;
        move |kid: String| {
            let local_resolver = resolver.clone();
            async move {
                let resp = dereference(&kid, None, local_resolver).await?;
                let Some(Resource::VerificationMethod(vm)) = resp.content_stream else {
                    return Err(anyhow!("Verification method not found"));
                };
                vm.method_type.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
            }
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

    /// An "overriding" signature for a web node owner or owner-delegate to
    /// store a message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}

/// Signature payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwsPayload {
    /// The CID of the message descriptor.
    pub descriptor_cid: String,

    /// The ID of the permission grant for the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,

    /// Entry ID of a permission grant web node `RecordsWrite` with `delegated` set to `true`.
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

    /// An "overriding" signature for a web node owner or owner-delegate to store a
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
    pub(crate) async fn authenticate(&self, resolver: impl DidResolver) -> Result<()> {
        // let verifier = verify_key!(resolver);
        self.signature.verify(verify_key!(resolver.clone())).await?;

        if let Some(signature) = &self.owner_signature {
            signature.verify(verify_key!(resolver.clone())).await?;
        }
        if let Some(grant) = &self.author_delegated_grant {
            grant.authorization.signature.verify(verify_key!(resolver.clone())).await?;
        }
        if let Some(grant) = &self.owner_delegated_grant {
            grant.authorization.signature.verify(verify_key!(resolver)).await?;
        }

        Ok(())
    }

    // TODO: cache this value
    /// Get message author's DID.
    pub(crate) fn author(&self) -> Result<String> {
        self.author_delegated_grant.as_ref().map_or_else(
            || signer_did(&self.signature),
            |grant| signer_did(&grant.authorization.signature),
        )
    }

    /// Get message owner's DID.
    pub(crate) fn owner(&self) -> Result<Option<String>> {
        let signer = if let Some(grant) = self.owner_delegated_grant.as_ref() {
            signer_did(&grant.authorization.signature)?
        } else {
            let Some(signature) = &self.owner_signature else {
                return Ok(None);
            };
            signer_did(signature)?
        };
        Ok(Some(signer))
    }

    /// Get message signer's DID from the message authorization.
    pub(crate) fn signer(&self) -> Result<String> {
        signer_did(&self.signature)
    }

    /// Get the owner's signing DID from the owner signature.
    pub(crate) fn owner_signer(&self) -> Result<String> {
        let Some(grant) = self.owner_delegated_grant.as_ref() else {
            return Err(unexpected!("owner delegated grant not found"));
        };
        signer_did(&grant.authorization.signature)
    }

    /// Get the JWS payload of the message.
    ///
    /// # Errors
    /// TODO: Add errors
    pub fn jws_payload(&self) -> Result<JwsPayload> {
        let base64 = &self.signature.payload;
        let decoded = Base64UrlUnpadded::decode_vec(base64)
            .map_err(|e| unexpected!("issue decoding header: {e}"))?;
        serde_json::from_slice(&decoded).map_err(|e| unexpected!("issue deserializing header: {e}"))
    }
}

/// Gets the DID of the signer of the given message, returning an error if the
/// message is not signed.
pub(crate) fn signer_did(jws: &Jws) -> Result<String> {
    let Some(kid) = jws.signatures[0].protected.kid() else {
        return Err(unexpected!("Invalid `kid`"));
    };
    let Some(did) = kid.split('#').next() else {
        return Err(unexpected!("Invalid DID"));
    };
    Ok(did.to_owned())
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub(crate) struct AuthorizationBuilder {
    descriptor_cid: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
}

/// Builder for creating a permission grant.
impl AuthorizationBuilder {
    /// Returns a new [`AuthorizationBuilder`]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Set the `Descriptor` CID.
    #[must_use]
    pub(crate) fn descriptor_cid(mut self, descriptor_cid: impl Into<String>) -> Self {
        self.descriptor_cid = Some(descriptor_cid.into());
        self
    }

    /// Set the `Descriptor`.
    #[must_use]
    pub(crate) fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Specify a grant ID to use.
    #[must_use]
    pub(crate) fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify a protocol role to use.
    #[must_use]
    pub(crate) fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
    pub(crate) async fn build(self, signer: &impl Signer) -> Result<Authorization> {
        let descriptor_cid =
            self.descriptor_cid.ok_or_else(|| unexpected!("descriptor not found"))?;
        let delegated_grant_id = if let Some(grant) = &self.delegated_grant {
            Some(cid::from_value(grant)?)
        } else {
            None
        };

        let payload = JwsPayload {
            descriptor_cid,
            permission_grant_id: self.permission_grant_id,
            delegated_grant_id,
            protocol_role: self.protocol_role,
        };
        let signature = JwsBuilder::new().payload(payload).build(signer).await?;

        Ok(Authorization {
            signature,
            author_delegated_grant: self.delegated_grant,
            owner_signature: None,
            owner_delegated_grant: None,
        })
    }
}
