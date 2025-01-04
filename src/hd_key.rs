#![allow(missing_docs)]

//! # Hierarchical Deterministic Key
//!
//! Hierarchical deterministic (HD) keys are a type of deterministic bitcoin
//! wallet derived from a known seed, that allow for the creation of child keys
//! from the parent key.

use std::fmt::{self, Display};
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vercre_infosec::jose::PublicKeyJwk;
use vercre_infosec::{Curve, KeyType};

use crate::{Error, Result, unexpected};

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

impl FromStr for DerivationScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "dataFormats" => Ok(Self::DataFormats),
            "protocolContext" => Ok(Self::ProtocolContext),
            "protocolPath" => Ok(Self::ProtocolPath),
            "schemas" => Ok(Self::Schemas),
            _ => Err(unexpected!("invalid derivation scheme")),
        }
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
///
/// # Errors
/// LATER: document errors
pub fn derive_jwk(
    ancestor_jwk: DerivedPrivateJwk, sub_derivation_path: &[String],
) -> Result<DerivedPrivateJwk> {
    let ancestor_secret = Base64UrlUnpadded::decode_vec(&ancestor_jwk.derived_private_key.d)?;

    // derive the descendant private key
    let derived_secret = derive_key(&ancestor_secret, sub_derivation_path)?;
    let secret_bytes: [u8; 32] =
        derived_secret.try_into().map_err(|_| unexpected!("invalid secret key"))?;

    // let derived_secret = StaticSecret::from(fixed);
    // let derived_public = PublicKey::from(&derived_secret);
    let derived_secret = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let derived_public =
        x25519_dalek::PublicKey::from(derived_secret.verifying_key().to_montgomery().to_bytes());

    // convert to JWK
    let derived_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(derived_public.as_bytes()),
            ..PublicKeyJwk::default()
        },
        d: Base64UrlUnpadded::encode_string(derived_secret.as_bytes()),
    };

    // return derived private JWK
    let mut derivation_path = ancestor_jwk.derivation_path.unwrap_or_default();
    derivation_path.extend(sub_derivation_path.to_vec());

    Ok(DerivedPrivateJwk {
        root_key_id: ancestor_jwk.root_key_id,
        derivation_scheme: ancestor_jwk.derivation_scheme,
        derivation_path: Some(derivation_path),
        derived_private_key: derived_jwk,
    })
}

/// Derives a hardened hierarchical deterministic private key using HKDF
/// (HMAC-based Extract-and-Expand Key Derivation Function).
///
/// # Errors
/// LATER: document errors
pub fn derive_key(private_key: &[u8], relative_path: &[String]) -> Result<Vec<u8>> {
    let mut derived_key = private_key.to_vec();

    for segment in relative_path {
        if segment.is_empty() {
            return Err(unexpected!("invalid key derivation path"));
        }
        let mut okm = [0u8; 32];
        // let salt = hex!(owner);// TODO: use owner as salt

        Hkdf::<Sha256>::new(None, &derived_key)
            .expand(segment.as_bytes(), &mut okm)
            .map_err(|e| anyhow!("issue expanding hkdf key: {e}"))?;
        derived_key = okm.to_vec();
    }

    Ok(derived_key)
}
