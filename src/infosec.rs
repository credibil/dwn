//! # Signing and Encryption

use serde::{Deserialize, Serialize};

/// JWS definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Jws {
    /// The stringified CID of the DAG CBOR encoded message `descriptor` property.
    /// An empty string when JWS Unencoded Payload Option used.
    pub payload: String,

    /// JWS signatures.
    pub signatures: Vec<Signature>,
}

/// An entry of the `signatures` array in a general JWS.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Signature {
    /// The base64 url-encoded JWS protected header when the JWS protected
    /// header is non-empty. Must have `alg` and `kid` properties set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    /// The base64 url-encoded JWS signature.
    pub signature: String,
}

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

/// Supported ncryption algorithms.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum EncryptionAlgorithm {
    /// AES 256 CTR.
    #[serde(rename = "A256CTR")]
    #[default]
    Aes256Ctr,

    /// AES 256 GCM.
    #[serde(rename = "ECIES-ES256K")]
    EciesSecp256k1,
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

/// JSON Web Key (JWK) definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    /// The algorithm intended for use with the key.
    pub alg: Option<String>,

    /// The key ID.
    pub kid: Option<String>,

    /// The cryptographic key type, e.g. "OKP", "EC".
    pub kty: String,

    /// The cryptographic curve used with the key, e.g. 'Ed25519', 'ES256k'
    pub crv: String,

    /// Base64url encoded x point.
    pub x: String,

    /// Base64url encoded y point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
