//! # Authorization

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use vercre_did::DidResolver;
pub use vercre_did::{dereference, Resource};
use vercre_infosec::jose::Type;
use vercre_infosec::{Jws, Signer};

pub use crate::permissions::grant::Grant;
use crate::{cid, records};

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

        move |kid: String| async move {
            let resp = dereference(&kid, None, resolver).await?;
            let Some(Resource::VerificationMethod(vm)) = resp.content_stream else {
                return Err(anyhow!("Verification method not found"));
            };
            vm.method_type.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
        }
    }};
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
    /// Returns a new [`GrantBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `Descriptor`.
    #[must_use]
    pub fn descriptor_cid(mut self, descriptor_cid: String) -> Self {
        self.descriptor_cid = Some(descriptor_cid);
        self
    }

    /// Specify a grant ID to use.
    #[must_use]
    pub fn permission_grant_id(mut self, permission_grant_id: String) -> Self {
        self.permission_grant_id = Some(permission_grant_id);
        self
    }

    /// Specify a protocol role to use.
    #[must_use]
    pub fn protocol_role(mut self, protocol_role: String) -> Self {
        self.protocol_role = Some(protocol_role);
        self
    }

    /// Generate the permission grant.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self, signer: &impl Signer) -> Result<Authorization> {
        let descriptor_cid = self.descriptor_cid.ok_or_else(|| anyhow!("descriptor not found"))?;
        let delegated_grant_id =
            if let Some(grant) = &self.delegated_grant { Some(cid::compute(grant)?) } else { None };

        let payload = SignaturePayload {
            descriptor_cid,
            permission_grant_id: self.permission_grant_id,
            delegated_grant_id,
            protocol_role: self.protocol_role,
        };
        let signature = Jws::new(Type::Jwt, &payload, signer).await?;

        Ok(Authorization {
            signature,
            author_delegated_grant: self.delegated_grant,
            owner_signature: None,
            owner_delegated_grant: None,
        })
    }
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

    /// The grant's descriptor.
    pub descriptor: records::WriteDescriptor,

    /// Encoded grant data.
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
    pub(crate) async fn authenticate(&self, resolver: &impl DidResolver) -> Result<()> {
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
    pub(crate) fn author(&self) -> Result<String> {
        self.author_delegated_grant.as_ref().map_or_else(
            || signer_did(&self.signature),
            |grant| signer_did(&grant.authorization.signature),
        )
    }
}

/// Gets the DID of the signer of the given message, returning an error if the
/// message is not signed.
pub(crate) fn signer_did(jws: &Jws) -> Result<String> {
    let Some(kid) = jws.signatures[0].protected.kid() else {
        return Err(anyhow!("Invalid `kid`"));
    };
    let Some(did) = kid.split('#').next() else {
        return Err(anyhow!("Invalid DID"));
    };
    Ok(did.to_owned())
}
