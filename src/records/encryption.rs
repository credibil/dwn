use base64ct::{Base64UrlUnpadded, Encoding};
use vercre_infosec::jose::jwe::{
    ContentAlgorithm, JweBuilder, KeyAlgorithm, PublicKey, Recipients,
};
use vercre_infosec::jose::{Curve, PublicKeyJwk};

use crate::hd_key::DerivationScheme;
use crate::records::write::{EncryptedKey, EncryptionProperty};
use crate::{Result, unexpected};

/// Encryption settings.
#[derive(Clone, Debug, Default)]
pub struct EncryptOptions {
    /// The algorithm to use to encrypt the message data.
    pub content_algorithm: ContentAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    pub key_algorithm: KeyAlgorithm,

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    pub recipients: Vec<Recipient>,
}

/// Encryption key settings.
#[derive(Clone, Debug, Default)]
pub struct Recipient {
    /// The identifier of the recipient's public key used to encrypt the
    /// content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key used to encrypt the CEK.
    pub public_key: PublicKeyJwk,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,
}

impl EncryptOptions {
    /// Create a new `EncryptionOptions`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_algorithm: ContentAlgorithm::A256Gcm,
            key_algorithm: KeyAlgorithm::EcdhEsA256Kw,
            recipients: vec![],
        }
    }

    /// Set the content encryption algorithm.
    #[must_use]
    pub const fn content_algorithm(mut self, algorithm: ContentAlgorithm) -> Self {
        self.content_algorithm = algorithm;
        self
    }

    /// Set the key encryption algorithm.
    #[must_use]
    pub const fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// Add a recipient to the encryption options.
    #[must_use]
    pub fn with_recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Encrypt the provided data using the specified encryption options.
    ///
    /// # Returns
    ///
    /// A tuple containing the encrypted data (ciphertext) and the settings
    /// used to encrypt it.
    ///
    /// # Errors
    /// LATER: Add error handling
    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, EncryptionProperty)> {
        // build JWE
        let mut builder = JweBuilder::new()
            .content_algorithm(ContentAlgorithm::A256Gcm)
            .key_algorithm(KeyAlgorithm::EcdhEsA256Kw)
            .payload(&data);

        for recipient in &self.recipients {
            let jwk = &recipient.public_key;
            let decoded = if jwk.crv == Curve::Ed25519 {
                Base64UrlUnpadded::decode_vec(&jwk.x)?
            } else {
                let mut decoded = Base64UrlUnpadded::decode_vec(&jwk.x)?;
                let Some(y) = &jwk.y else {
                    return Err(unexpected!("missing y"));
                };
                decoded.extend(&Base64UrlUnpadded::decode_vec(y)?);
                decoded
            };

            let mut map = serde_json::Map::new();
            map.insert(
                "derivationScheme".to_string(),
                serde_json::Value::String(recipient.derivation_scheme.to_string()),
            );
            map.insert(
                "derivedPublicKey".to_string(),
                serde_json::to_value(&recipient.public_key)?,
            );

            builder = builder.add_recipient(
                &recipient.key_id,
                PublicKey::from_slice(&decoded)?,
                Some(map),
            );
        }

        let jwe = builder.build()?;

        // use JWE to build EncryptionProperty
        let mut encryption = EncryptionProperty {
            algorithm: jwe.protected.enc.clone(),
            initialization_vector: jwe.iv.clone(),
            key_encryption: vec![],
        };

        let recipients = match &jwe.recipients {
            Recipients::One(recipient) => vec![recipient.clone()],
            Recipients::Many { recipients } => recipients.clone(),
        };

        for recipient in &recipients {
            let header = &recipient.header;
            let Some(key_id) = header.kid.clone() else {
                return Err(unexpected!("missing key id"));
            };
            let Some(key_input) = self.recipients.iter().find(|r| r.key_id == key_id) else {
                return Err(unexpected!("recipient not found"));
            };

            //     if recipient.derivation_scheme == DerivationScheme::ProtocolPath
            //         && self.descriptor.protocol.is_none()
            //     {
            //         return Err(unexpected!(
            //             "`protocol` must be specified to use `protocols` encryption scheme"
            //         ));
            //     }
            //     if key_input.derivation_scheme == DerivationScheme::Schemas
            //         && self.descriptor.schema.is_none()
            //     {
            //         return Err(unexpected!(
            //             "`schema` must be specified to use `schema` encryption scheme"
            //         ));
            //     }

            let mut encrypted = EncryptedKey {
                root_key_id: key_id,
                algorithm: header.alg.clone(),
                ephemeral_public_key: header.epk.clone(),
                initialization_vector: header.iv.clone(),
                message_authentication_code: header.tag.clone(),
                encrypted_key: recipient.encrypted_key.clone(),
                derivation_scheme: key_input.derivation_scheme.clone(),
                derived_public_key: None,
            };

            // attach the public key when derivation scheme is protocol-context,
            // so that the responder to this message is able to encrypt the
            // content encryption key using the same protocol-context derived
            // public key, without needing the knowledge of the corresponding
            // private key
            if key_input.derivation_scheme == DerivationScheme::ProtocolContext {
                encrypted.derived_public_key = Some(key_input.public_key.clone());
            }

            encryption.key_encryption.push(encrypted);
        }

        Ok((Base64UrlUnpadded::decode_vec(&jwe.ciphertext)?, encryption))
    }
}
