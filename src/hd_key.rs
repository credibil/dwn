//! # Hierarchical Deterministic Key
//!
//! Hierarchical deterministic (HD) keys are a tree-like structure of keys
//! derived from a single root or seed key.
//!
//! In the case of a DWN implementation, HD keys are used to derive a hierarchy
//! of encryption keys from a parent key provided by the DWN owner. The derived
//! keys can be distributed to participating parties to allow them to encrypt
//! data that can be decrypted by parties higher up the tree, including the
//! owner.
//!
//! Derived private keys are typically encrypted (using the recipient's public
//! key) and distributed  ahead of their actual use.

use std::fmt::{self, Display};
use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::jose::PublicKeyJwk;
use credibil_infosec::{Curve, KeyType};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Error, Result, unexpected};

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DerivationScheme {
    /// Key derivation using the `data_format` value for flat-space (non-
    /// protocol-based) records.
    #[default]
    DataFormats,

    /// Key derivation using the `schema` value for flat-space (non-
    /// protocol-based) records.
    Schemas,

    /// Key derivation using protocol context.
    ProtocolContext,

    /// Key derivation using the protocol path.
    ProtocolPath,
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
    /// The private key's public key component.
    #[serde(flatten)]
    pub public_key: PublicKeyJwk,

    /// The private key's secret component.
    pub d: String,
}

/// A derived private key data structure containing information related to the
/// key derivation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DerivedPrivateJwk {
    /// The key ID of the root key this key has been derived from.
    pub root_key_id: String,

    /// The key derivation scheme used to derive this key.
    pub derivation_scheme: DerivationScheme,

    /// The derivation path for this key.
    pub derivation_path: Option<Vec<String>>,

    /// The derived private key.
    pub derived_private_key: PrivateKeyJwk,
}

/// The hierarchical deterministic key derivation path.
pub enum DerivationPath<'a> {
    /// A full path from the root key to the descendant key.
    Full(&'a [String]),

    /// A relative path from the ancestor key to the descendant key.
    Relative(&'a [String]),
}

// FIXME: currently only supports Ed25519 keys.
/// Derives a descendant private key.
///
/// # Errors
///
/// This function will fail when:
///
/// - The ancestor and descendant key derivation paths do not match.
/// - The secret key is invalid.
pub fn derive_jwk(ancestor: DerivedPrivateJwk, path: &DerivationPath) -> Result<DerivedPrivateJwk> {
    let empty_path = vec![];
    let ancestor_path = ancestor.derivation_path.as_ref().unwrap_or(&empty_path);

    let sub_path = match path {
        DerivationPath::Full(descendant_path) => {
            // validate initial part of descendant path matches ancestor
            for (i, segment) in ancestor_path.iter().enumerate() {
                if segment != &descendant_path[i] {
                    return Err(unexpected!(
                        "ancestor and descendant key derivation segments do not match"
                    ));
                }
            }

            // derive keypair for the descendant sub-path, i.e. the difference between
            // the ancestor and full descendant paths
            &descendant_path[ancestor_path.len()..]
        }
        DerivationPath::Relative(sub_path) => sub_path,
    };

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

    let mut derivation_path = ancestor_path.clone();
    derivation_path.extend_from_slice(sub_path);

    Ok(DerivedPrivateJwk {
        root_key_id: ancestor.root_key_id,
        derivation_scheme: ancestor.derivation_scheme,
        derivation_path: Some(derivation_path),
        derived_private_key: derived_jwk,
    })
}

/// Derives a hardened hierarchical deterministic private key using HKDF
/// (HMAC-based Extract-and-Expand Key Derivation Function).
///
/// # Errors
///
/// This function will fail when the key derivation path has an empty segment
/// or the HKDF key expansion fails.
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
