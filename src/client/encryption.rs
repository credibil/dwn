//! # Encryption
//!
//! This module provides data structures and functions used in the encrypting
//! and decrypting of [`Write`] data.

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_jose::jwe::{self, Header, Jwe, KeyEncryption, Protected, Recipients};
use credibil_se::{Receiver, derive_x25519_secret};

use crate::hd_key::{self, DerivationPath, DerivationScheme, DerivedPrivateJwk};
use crate::interfaces::records::{EncryptedKey, Write};

/// Decrypt the provided data using the encryption properties specified in the
/// `Write` message.
///
/// # Errors
///
/// Will fail if the encryption properties are not set or if the data cannot be
/// decrypted using the provided encryption properties.
pub async fn decrypt(
    data: &[u8], write: &Write, ancestor_jwk: &DerivedPrivateJwk, _: &impl Receiver,
) -> Result<Vec<u8>> {
    let Some(encryption) = &write.encryption else {
        return Err(anyhow!("encryption parameter not set"));
    };
    let Some(recipient) = encryption.key_encryption.iter().find(|k| {
        k.root_key_id == ancestor_jwk.root_key_id
            && k.derivation_scheme == ancestor_jwk.derivation_scheme
    }) else {
        return Err(anyhow!("encryption key not found"));
    };

    // ------------------------------------------------------------------------
    // TODO: move this code to Provider
    // ------------------------------------------------------------------------
    // derive path-appropriate JWK from ancestor
    let path = derivation_path(recipient, write)?;
    let derived_jwk = hd_key::derive_jwk(ancestor_jwk.clone(), &DerivationPath::Full(&path))?;
    let receiver = ReceiverImpl(derived_jwk.derived_private_key.d.clone());
    // ------------------------------------------------------------------------

    // recreate JWE
    let protected = Protected {
        enc: encryption.algorithm.clone(),
        alg: None,
    };
    let aad = serde_json::to_vec(&protected)?;

    let jwe = Jwe {
        protected,
        unprotected: None,
        recipients: Recipients::One(KeyEncryption {
            header: Header {
                alg: recipient.algorithm.clone(),
                kid: Some(recipient.root_key_id.clone()),
                epk: recipient.ephemeral_public_key.clone(),
                iv: recipient.initialization_vector.clone(),
                tag: recipient.message_authentication_code.clone(),
            },
            encrypted_key: recipient.cek.clone(),
        }),
        aad: Base64UrlUnpadded::encode_string(&aad),
        iv: encryption.initialization_vector.clone(),
        tag: encryption.message_authentication_code.clone().unwrap_or_default(),
        ciphertext: Base64UrlUnpadded::encode_string(data),
    };

    let plaintext: Vec<u8> =
        jwe::decrypt_bytes(&jwe, &receiver).await.context("decrypting JWE")?;

    Ok(plaintext)
}

fn derivation_path(encrypted_key: &EncryptedKey, write: &Write) -> Result<Vec<String>> {
    let descriptor = &write.descriptor;

    let derivation_path = match &encrypted_key.derivation_scheme {
        DerivationScheme::DataFormats => {
            let scheme = DerivationScheme::DataFormats.to_string();
            if let Some(schema) = &descriptor.schema {
                vec![scheme, schema.clone(), descriptor.data_format.clone()]
            } else {
                vec![scheme, descriptor.data_format.clone()]
            }
        }
        DerivationScheme::ProtocolPath => {
            let Some(protocol) = &descriptor.protocol else {
                return Err(anyhow!("`protocol` not set"));
            };
            let Some(protocol_path) = &descriptor.protocol_path else {
                return Err(anyhow!("`protocol_path` not set"));
            };

            let segments =
                protocol_path.split('/').map(ToString::to_string).collect::<Vec<String>>();
            let mut path = vec![DerivationScheme::ProtocolPath.to_string(), protocol.clone()];
            path.extend(segments);
            path
        }
        DerivationScheme::ProtocolContext => {
            let Some(context_id) = &write.context_id else {
                return Err(anyhow!("`context_id` not set"));
            };
            let segments = context_id.split('/').map(ToString::to_string).collect::<Vec<String>>();
            vec![DerivationScheme::ProtocolContext.to_string(), segments[0].clone()]
        }
        DerivationScheme::Schemas => {
            let Some(schema) = &descriptor.schema else {
                return Err(anyhow!("`schema` not set"));
            };
            vec![DerivationScheme::Schemas.to_string(), schema.clone()]
        }
    };

    Ok(derivation_path)
}

use credibil_se::{PUBLIC_KEY_LENGTH, PublicKey, SharedSecret};

struct ReceiverImpl(String);

impl Receiver for ReceiverImpl {
    async fn key_id(&self) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
        // EdDSA signing key
        let decoded = Base64UrlUnpadded::decode_vec(&self.0)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        derive_x25519_secret(&bytes, &sender_public)
    }
}
