//! # Authorization
//!
//! The `Authorization` module groups types and functionality loosely related
//! to message authorization and authentication.

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::{DidResolver, Resource, dereference};
use credibil_infosec::jose::JwsBuilder;
use credibil_infosec::{Jws, Signer};
use serde::{Deserialize, Serialize};

use crate::interfaces::records::DelegatedGrant;
use crate::utils::cid;
use crate::{Result, unexpected};

/// Creates a closure to resolve pub key material required by `Jws::decode`.
///
/// # Example
///
/// ```rust,ignore
/// use credibil_infosec::{verify_key, SecOps};
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
                let resp = dereference(&kid, None, local_resolver)
                    .await
                    .map_err(|e| anyhow!("issue dereferencing DID: {e}"))?;
                let Some(Resource::VerificationMethod(vm)) = resp.content_stream else {
                    return Err(anyhow!("Verification method not found"));
                };
                vm.method_type.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
            }
        }
    }};
}

/// JWS signature payload for message authorization.
///
/// The payload is used to attest to the veracity of the message by providing
/// the means to verify the message's contents and permissions.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwsPayload {
    /// The CID (CBOR hash) of the message descriptor.
    pub descriptor_cid: String,

    /// The Entry ID (`record_id`) of the permission grant `RecordsWrite`
    /// message used to authorize the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,

    /// The Entry ID (`record_id`) of the delegated permission grant
    /// `RecordsWrite` message used to authorize the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_grant_id: Option<String>,

    /// Used to authorize role-authorized actions for protocol records in the
    /// Records interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_role: Option<String>,
}

/// Message authorization.
///
/// Used in messages that require authorization material for processing in
/// accordance with the permissions specified by the web node owner.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The message signer's signature.
    /// N.B.: May be the signature of a delegate of the author's.
    pub signature: Jws,

    /// An "overriding" signature for use by a web node owner or owner-delegate
    /// when storing a message authored by another entity.
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

impl Authorization {
    /// Verify message signature.
    pub(crate) async fn verify(&self, resolver: impl DidResolver) -> Result<()> {
        let verifier = verify_key!(resolver);

        self.signature.verify(verifier.clone()).await?;
        if let Some(signature) = &self.owner_signature {
            signature.verify(verifier.clone()).await?;
        }
        if let Some(grant) = &self.author_delegated_grant {
            grant.authorization.signature.verify(verifier.clone()).await?;
        }
        if let Some(grant) = &self.owner_delegated_grant {
            grant.authorization.signature.verify(verifier).await?;
        }

        Ok(())
    }

    /// Extract message author's DID from the message authorization.
    ///
    /// # Errors
    ///
    /// This method will return an error if the author's DID cannot be
    /// retrieved from the message signature or the signature of the
    /// author-delegate.
    pub fn author(&self) -> Result<String> {
        self.author_delegated_grant
            .as_ref()
            .map_or_else(|| self.signature.did(), |grant| grant.authorization.signature.did())
            .map_err(|e| unexpected!("issue getting author's DID: {e}"))
    }

    /// Get message owner's DID.
    pub(crate) fn owner(&self) -> Result<Option<String>> {
        let signer = if let Some(grant) = self.owner_delegated_grant.as_ref() {
            grant.authorization.signature.did()?
        } else {
            let Some(signature) = &self.owner_signature else {
                return Ok(None);
            };
            signature.did()?
        };
        Ok(Some(signer))
    }

    /// Get message signer's DID from the message authorization.
    pub(crate) fn signer(&self) -> Result<String> {
        self.signature.did().map_err(|e| unexpected!("issue getting signer's DID: {e}"))
    }

    /// Get the owner's signing DID from the owner signature.
    pub(crate) fn owner_signer(&self) -> Result<String> {
        let Some(grant) = self.owner_delegated_grant.as_ref() else {
            return Err(unexpected!("owner delegated grant not found"));
        };
        grant
            .authorization
            .signature
            .did()
            .map_err(|e| unexpected!("issue getting owner's DID: {e}"))
    }

    /// Extract the JWS payload from the authorization's signature.
    ///
    /// # Errors
    ///
    /// Will return an error if the payload cannot be decoded or deserialized.
    pub fn payload(&self) -> Result<JwsPayload> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.signature.payload)
            .map_err(|e| unexpected!("issue decoding signature payload: {e}"))?;
        serde_json::from_slice(&decoded)
            .map_err(|e| unexpected!("issue deserializing signature payload: {e}"))
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct AuthorizationBuilder {
    descriptor_cid: Option<String>,
    delegated_grant: Option<DelegatedGrant>,
    permission_grant_id: Option<String>,
    protocol_role: Option<String>,
}

/// Builder for creating a permission grant.
impl AuthorizationBuilder {
    /// Returns a new [`AuthorizationBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `Descriptor` CID.
    #[must_use]
    pub fn descriptor_cid(mut self, descriptor_cid: impl Into<String>) -> Self {
        self.descriptor_cid = Some(descriptor_cid.into());
        self
    }

    /// Set the `Descriptor`.
    #[must_use]
    pub fn delegated_grant(mut self, delegated_grant: DelegatedGrant) -> Self {
        self.delegated_grant = Some(delegated_grant);
        self
    }

    /// Specify a grant ID to use.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: impl Into<String>) -> Self {
        self.permission_grant_id = Some(permission_grant_id.into());
        self
    }

    /// Specify a protocol role to use.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: impl Into<String>) -> Self {
        self.protocol_role = Some(protocol_role.into());
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    ///
    /// Will return an error when an incorrect value has been provided or when
    /// there was an issue signing the Authorization
    pub async fn build(self, signer: &impl Signer) -> Result<Authorization> {
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
        let signature = JwsBuilder::new().payload(payload).add_signer(signer).build().await?;

        Ok(Authorization {
            signature,
            author_delegated_grant: self.delegated_grant,
            owner_signature: None,
            owner_delegated_grant: None,
        })
    }
}
