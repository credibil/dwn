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
use ed25519_dalek::PUBLIC_KEY_LENGTH;
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

// FIXME: currently only supports Ed25519 keys.
/// Derives a descendant private key.
///
/// # Errors
/// LATER: document errors
pub fn derive_jwk(
    ancestor: DerivedPrivateJwk, descendant_path: &[String],
) -> Result<DerivedPrivateJwk> {
    let empty_path = vec![];
    let ancestor_path = ancestor.derivation_path.as_ref().unwrap_or(&empty_path);

    // validate initial part of descendant path matches ancestor
    if ancestor_path.as_slice() != &descendant_path[0..ancestor_path.len()] {
        return Err(unexpected!("ancestor and descendant key derivation segments do not match"));
    }

    // derive keypair for the descendant sub-path, i.e. the difference between 
    // the ancestor and full descendant paths
    let sub_path = &descendant_path[ancestor_path.len()..];

    let ancestor_secret = Base64UrlUnpadded::decode_vec(&ancestor.derived_private_key.d)?;
    let secret_bytes: [u8; PUBLIC_KEY_LENGTH] =
        ancestor_secret.try_into().map_err(|_| unexpected!("invalid secret key"))?;

    // derive descendant private/public keypair
    let derived_secret = derive_key(secret_bytes, sub_path)?;

    // FIXME: don't assume we are using Ed25519 with need to convert to X25519
    //        !!check `Curve` value
    let derived_signing = ed25519_dalek::SigningKey::from_bytes(&derived_secret);
    let derived_public =
        x25519_dalek::PublicKey::from(derived_signing.verifying_key().to_montgomery().to_bytes());

    // convert to JWK
    let derived_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(derived_public.as_bytes()),
            ..PublicKeyJwk::default()
        },
        d: Base64UrlUnpadded::encode_string(&derived_secret),
    };

    Ok(DerivedPrivateJwk {
        root_key_id: ancestor.root_key_id,
        derivation_scheme: ancestor.derivation_scheme,
        derivation_path: Some(descendant_path.to_vec()),
        derived_private_key: derived_jwk,
    })
}

/// Derives a hardened hierarchical deterministic private key using HKDF
/// (HMAC-based Extract-and-Expand Key Derivation Function).
///
/// # Errors
/// LATER: document errors
pub fn derive_key(
    from_key: [u8; PUBLIC_KEY_LENGTH], path: &[String],
) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
    let mut derived_key = from_key;

    for segment in path {
        if segment.is_empty() {
            return Err(unexpected!("invalid key derivation path"));
        }
        let mut okm = [0u8; PUBLIC_KEY_LENGTH];
        // let salt = hex!(owner); // TODO: use owner as salt

        Hkdf::<Sha256>::new(None, &derived_key)
            .expand(segment.as_bytes(), &mut okm)
            .map_err(|e| anyhow!("issue expanding hkdf key: {e}"))?;
        derived_key = okm;
    }

    Ok(derived_key)
}
