//! # Authorization

use anyhow::{anyhow, Result};
use vercre_infosec::Jws;

use crate::provider::DidResolver;
use crate::service::Authorization;

//   public async verifySignatures(jws: Jws, didResolver: DidResolver): Promise<VerificationResult> {
//     const signers: string[] = [];

//     for (const signatureEntry of jws.signatures) {
//       let isVerified: boolean;
//       const kid = Jws.getKid(signatureEntry);

//       const cacheKey = `${signatureEntry.protected}.${jws.payload}.${signatureEntry.signature}`;
//       const cachedValue = await this.cache.get(cacheKey);

//       // explicit `undefined` check to differentiate `false`
//       if (cachedValue === undefined) {
//         const publicJwk = await GeneralJwsVerifier.getPublicKey(kid, didResolver);
//         isVerified = await Jws.verifySignature(jws.payload, signatureEntry, publicJwk);
//         await this.cache.set(cacheKey, isVerified);
//       } else {
//         isVerified = cachedValue;
//       }

//       const did = Jws.extractDid(kid);

//       if (isVerified) {
//         signers.push(did);
//       } else {
//         throw new DwnError(DwnErrorCode.GeneralJwsVerifierInvalidSignature, `Signature verification failed for ${did}`);
//       }
//     }

//     return { signers };
//   }

/// Verify message signatures.
pub async fn authenticate(authzn: Authorization, resolver: &impl DidResolver) -> Result<()> {
    verify_signatures(authzn.signature, resolver)?;

    if let Some(signature) = authzn.owner_signature {
        verify_signatures(signature, resolver)?;
    }
    if let Some(grant) = authzn.author_delegated_grant {
        verify_signatures(grant.authorization.signature, resolver)?;
    }
    if let Some(grant) = authzn.owner_delegated_grant {
        verify_signatures(grant.authorization.signature, resolver)?;
    }

    Ok(())
}

/// Verify JWS signatures.
fn verify_signatures(jws: Jws, resolver: &impl DidResolver) -> Result<()> {
    let mut signers: Vec<String> = vec![];

    for signature in jws.signatures {
        let mut verified = false;

        // let jwt: jws::Jwt<ProofClaims> =
        //     match jws::decode(proof_jwt, verify_key!(provider)).await {
        //         Ok(jwt) => jwt,
        //         Err(e) => {
        //             return Err(self
        //                 .invalid_proof(provider, format!("issue decoding JWT: {e}"))
        //                 .await?);
        //         }
        //     };

        // let kid = Jws::get_kid(&signature);
        // let public_jwk = Jws::get_public_key(kid, resolver).await?;
        // verified = Jws::verify_signature(jws.payload, signature, public_jwk).await?;

        // let protected = signature.protected.unwrap_or_default();
        // let cache_key = format!("{}.{}.{}", protected, jws.payload, signature.signature);
        // let cached_value = self.cache.get(cache_key).await;

        // if let Some(cached_value) = cached_value {
        //     let public_jwk = Jws::get_public_key(kid, resolver).await?;
        //     verified = Jws::verify_signature(jws.payload, signature, public_jwk).await?;
        //     self.cache.set(cache_key, is_verified).await;
        // } else {
        //     verified = cached_value;
        // }

        // let did = Jws::extract_did(kid);

        if verified {
            // signers.push(did);
        } else {
            // return Err(anyhow!("Signature verification failed for {}", did));
        }
    }

    Ok(())
}
