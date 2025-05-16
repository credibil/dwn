//! # Authorization
//!
//! The `Authorization` module groups types and functionality loosely related
//! to message authorization and authentication.

#[cfg(feature = "server")]
use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(feature = "server")]
use credibil_identity::{IdentityResolver, did::Resource};
use credibil_identity::{SignerExt, did};
use credibil_jose::{Jws, JwsBuilder, Jwt, PublicKeyJwk};
use serde::{Deserialize, Serialize};

use crate::api::Result;
use crate::bad_request;
use crate::interfaces::records::DelegatedGrant;
use crate::utils::cid;

/// JWS signature payload for message authorization.
///
/// The payload is used to attest to the veracity of the message by providing
/// the means to verify the message's contents and permissions.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JwsPayload {
    /// The CID (CBOR hash) of the message descriptor.
    pub descriptor_cid: String,

    /// The Storable ID (`record_id`) of the permission grant `RecordsWrite`
    /// message used to authorize the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_grant_id: Option<String>,

    /// The Storable ID (`record_id`) of the delegated permission grant
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
    #[cfg(feature = "server")]
    pub(crate) async fn verify(&self, resolver: &impl IdentityResolver) -> Result<()> {
        let resolver = async |kid: String| did_jwk(&kid, resolver).await;

        let _: Jwt<JwsPayload> = self
            .signature
            .verify(resolver)
            .await
            .map_err(|e| bad_request!("issue verifying signature: {e}"))?;
        if let Some(signature) = &self.owner_signature {
            let _: Jwt<JwsPayload> = signature
                .verify(resolver)
                .await
                .map_err(|e| bad_request!("issue verifying owner signature: {e}"))?;
        }
        if let Some(grant) = &self.author_delegated_grant {
            let _: Jwt<JwsPayload> = grant
                .authorization
                .signature
                .verify(resolver)
                .await
                .map_err(|e| bad_request!("issue verifying author delegate signature: {e}"))?;
        }
        if let Some(grant) = &self.owner_delegated_grant {
            let _: Jwt<DelegatedGrant> = grant
                .authorization
                .signature
                .verify(resolver)
                .await
                .map_err(|e| bad_request!("issue verifying owner delegate signature: {e}"))?;
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
            .map_or_else(
                || kid_did(&self.signature),
                |grant| kid_did(&grant.authorization.signature),
            )
            .map_err(|e| bad_request!("issue getting author's DID: {e}"))
    }

    /// Get message owner's DID.
    #[cfg(feature = "server")]
    pub(crate) fn owner(&self) -> Result<Option<String>> {
        let signer = if let Some(grant) = self.owner_delegated_grant.as_ref() {
            kid_did(&grant.authorization.signature)?
        } else {
            let Some(signature) = &self.owner_signature else {
                return Ok(None);
            };
            kid_did(signature)?
        };
        Ok(Some(signer))
    }

    /// Get message signer's DID from the message authorization.
    pub(crate) fn signer(&self) -> Result<String> {
        kid_did(&self.signature).map_err(|e| bad_request!("issue getting signer's DID: {e}"))
    }

    /// Get the owner's signing DID from the owner signature.
    #[cfg(feature = "server")]
    pub(crate) fn owner_signer(&self) -> Result<String> {
        let Some(grant) = self.owner_delegated_grant.as_ref() else {
            return Err(bad_request!("owner delegated grant not found"));
        };
        kid_did(&grant.authorization.signature)
            .map_err(|e| bad_request!("issue getting owner's DID: {e}"))
    }

    /// Extract the JWS payload from the authorization's signature.
    ///
    /// # Errors
    ///
    /// Will return an error if the payload cannot be decoded or deserialized.
    pub fn payload(&self) -> Result<JwsPayload> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.signature.payload)
            .map_err(|e| bad_request!("issue decoding signature payload: {e}"))?;
        serde_json::from_slice(&decoded)
            .map_err(|e| bad_request!("issue deserializing signature payload: {e}"))
    }
}

/// Extract the DID from the provided JWS.
///
/// # Errors
///
/// Will return an error if the `kid` cannot be extracted from the JWS or if
/// the `kid` is not a valid DID.
pub fn kid_did(jws: &Jws) -> Result<String> {
    let Some(kid) = jws.signatures[0].protected.kid() else {
        return Err(bad_request!("Invalid `kid`"));
    };
    let Some(did) = kid.split('#').next() else {
        return Err(bad_request!("Invalid DID"));
    };
    Ok(did.to_owned())
}

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn did_jwk<R>(did_url: &str, resolver: &R) -> anyhow::Result<PublicKeyJwk>
where
    R: IdentityResolver + Send + Sync,
{
    let deref = did::dereference(did_url, resolver)
        .await
        .map_err(|e| anyhow!("issue dereferencing DID URL: {e}"))?;
    let Resource::VerificationMethod(vm) = deref else {
        return Err(anyhow!("Verification method not found"));
    };
    vm.key.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
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
    pub async fn build(self, signer: &impl SignerExt) -> Result<Authorization> {
        let descriptor_cid =
            self.descriptor_cid.ok_or_else(|| bad_request!("descriptor not found"))?;
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
        let key = signer.verification_method().await?;
        let key_ref = key.try_into()?;
        let signature =
            JwsBuilder::new().payload(payload).add_signer(signer).key_ref(&key_ref).build().await?;

        Ok(Authorization {
            signature,
            author_delegated_grant: self.delegated_grant,
            owner_signature: None,
            owner_delegated_grant: None,
        })
    }
}
