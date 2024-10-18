//! # Signing and Encryption

use serde::{Deserialize, Serialize};
use vercre_infosec::jose::{EncryptionAlgorithm, PublicKeyJwk};

/// Encryption settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Encryption {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The encrypted CEK.
    pub key_encryption: Vec<EncryptedKey>,
}

/// Encrypted key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the root public key used to encrypt the symmetric encryption key.
    pub root_key_d: String,

    /// The derived public key.
    pub derived_public_key: Option<PublicKeyJwk>,

    /// Encryption key derivation scheme.
    pub derivation_scheme: Option<KeyDerivationScheme>,

    /// The encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The ephemeral public key.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The MAC
    pub message_authentication_code: String,

    /// The encrypted key.
    pub encrypted_key: String,
}

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum KeyDerivationScheme {
    /// Key derivation using the `dataFormat` value for Flat-space records.
    #[serde(rename = "dataFormats")]
    #[default]
    DataFormats,

    /// Key derivation using protocol context.
    #[serde(rename = "protocolContext")]
    ProtocolContext,

    /// Key derivation using the protocol path.
    #[serde(rename = "protocolPath")]
    ProtocolPath,

    /// Key derivation using the `schema` value for Flat-space records.
    #[serde(rename = "schemas")]
    Schemas,
}
