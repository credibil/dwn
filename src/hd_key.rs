#![allow(missing_docs)]

//! # Hierarchical Deterministic Key
//!
//! Hierarchical deterministic (HD) keys are a type of deterministic bitcoin
//! wallet derived from a known seed, that allow for the creation of child keys
//! from the parent key.

use std::fmt::{self, Display};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SecretKey, SigningKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vercre_infosec::jose::PublicKeyJwk;
use vercre_infosec::{Curve, KeyType};

use crate::{Result, unexpected};

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DerivationScheme {
    /// Key derivation using the `dataFormat` value for Flat-space records.
    #[default]
    DataFormats,

    /// Key derivation using protocol context.
    ProtocolContext,

    /// Key derivation using the protocol path.
    ProtocolPath,

    /// Key derivation using the `schema` value for Flat-space records.
    Schemas,
}

impl Display for DerivationScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scheme = match self {
            Self::DataFormats => "dataFormats",
            Self::ProtocolContext => "protocolContext",
            Self::ProtocolPath => "protocolPath",
            Self::Schemas => "schemas",
        };
        write!(f, "{scheme}")
    }
}

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrivateKeyJwk {
    #[serde(flatten)]
    pub public_key: PublicKeyJwk,

    pub d: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DerivedPrivateJwk {
    pub root_key_id: String,
    pub derivation_scheme: DerivationScheme,
    pub derivation_path: Option<Vec<String>>,
    pub derived_private_key: PrivateKeyJwk,
}

/// Derives a descendant private key.
/// NOTE: currently only supports Ed25519 keys.
pub async fn derive_private_key(
    ancestor_key: DerivedPrivateJwk, sub_derivation_path: &[String],
) -> Result<DerivedPrivateJwk> {
    let ancestor_private_key = Base64UrlUnpadded::decode_vec(&ancestor_key.derived_private_key.d)?;

    // derive the descendant private key
    let derived_key = derive_key(&ancestor_private_key, sub_derivation_path).await?;

    // convert to JWK
    let derived_secret: SecretKey =
        derived_key.try_into().map_err(|_| unexpected!("invalid secret key"))?;
    let signing_key: SigningKey = SigningKey::from_bytes(&derived_secret);

    let derived_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(signing_key.verifying_key().as_bytes()),
            ..PublicKeyJwk::default()
        },
        d: Base64UrlUnpadded::encode_string(&derived_secret),
    };

    // return derived private JWK
    let mut derivation_path = ancestor_key.derivation_path.unwrap_or_default();
    derivation_path.extend(sub_derivation_path.to_vec());

    Ok(DerivedPrivateJwk {
        root_key_id: ancestor_key.root_key_id,
        derivation_scheme: ancestor_key.derivation_scheme,
        derivation_path: Some(derivation_path),
        derived_private_key: derived_jwk,
    })
}

/// Derives a hardened hierarchical deterministic private key using HKDF
/// (HMAC-based Extract-and-Expand Key Derivation Function).
pub async fn derive_key(private_key: &[u8], relative_path: &[String]) -> Result<Vec<u8>> {
    let mut derived_key = private_key.to_vec();

    for segment in relative_path {
        // check no empty strings exist within the derivation
        if segment.is_empty() {
            return Err(unexpected!("invalid key derivation path"));
        }
        let info = Base64UrlUnpadded::decode_vec(&segment)?;
        let mut okm = [0u8; 32];
        // let salt = hex!(owner);// TODO: use owner as salt

        Hkdf::<Sha256>::new(None, &derived_key)
            .expand(&info, &mut okm)
            .map_err(|e| anyhow!("issue expanding hkdf key: {e}"))?;
        derived_key = okm.to_vec();
    }

    return Ok(derived_key);
}
