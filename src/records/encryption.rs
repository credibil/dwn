//! # Encryption
//!
//! This module provides data structures and functions used in the encrypting
//! and decrypting of [`Write`] data.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use credibil_infosec::Receiver;
use credibil_infosec::jose::jwe::{
    self, ContentAlgorithm, Header, KeyAlgorithm, KeyEncryption, Protected, Recipients,
};
use credibil_infosec::jose::{Curve, Jwe, PublicKeyJwk};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hd_key::{self, DerivationPath, DerivationScheme, DerivedPrivateJwk};
use crate::records::Write;
use crate::{Result, unexpected};

/// Encryption settings.
#[derive(Clone, Debug, Default)]
pub struct EncryptOptions<'a> {
    /// The algorithm to use to encrypt the message data.
    content_algorithm: ContentAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    key_algorithm: KeyAlgorithm,

    /// The data to encrypt.
    data: &'a [u8],

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    recipients: Vec<Recipient>,
}

/// Encrypted data. Intermediate work product.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encrypted {
    /// The algorithm to use to encrypt the message data.
    #[zeroize(skip)]
    content_algorithm: ContentAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    #[zeroize(skip)]
    key_algorithm: KeyAlgorithm,

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    #[zeroize(skip)]
    pub recipients: Vec<Recipient>,

    /// The content encryption key (CEK) used to encrypt the data.
    pub cek: Vec<u8>,

    /// The initialization vector (IV) used to encrypt the data.
    pub iv: String,

    /// The additional authenticated data (AAD) used to encrypt the data.
    pub tag: String,

    /// The ciphertext.
    pub ciphertext: Vec<u8>,
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

impl<'a> EncryptOptions<'a> {
    /// Create a new `EncryptionOptions`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_algorithm: ContentAlgorithm::A256Gcm,
            key_algorithm: KeyAlgorithm::EcdhEsA256Kw,
            data: &[],
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

    /// Set the data to encrypt.
    #[must_use]
    pub const fn data(mut self, data: &'a [u8]) -> Self {
        self.data = data;
        self
    }

    /// Add a recipient to the encryption options.
    #[must_use]
    pub fn with_recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Encrypt the data using the specified encryption options, retaining the
    /// CEK, IV, and AAD tag for later use.
    ///
    /// # Errors
    ///
    /// Will fail if the [`Protected`] struct cannot be serialized to JSON or
    /// if the provided data cannot be encrypted using the specified content
    /// encryption algorithm.
    pub fn encrypt(&mut self) -> Result<Encrypted> {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::KeyInit;

        let cek = Aes256Gcm::generate_key(&mut rand::thread_rng());
        let protected = Protected {
            enc: self.content_algorithm.clone(),
            alg: None,
        };
        let aad = serde_json::to_vec(&protected)?;

        let encrypted = match self.content_algorithm {
            ContentAlgorithm::A256Gcm => jwe::a256gcm(self.data, &cek.into(), &aad)?,
            ContentAlgorithm::XChaCha20Poly1305 => {
                jwe::xchacha20_poly1305(self.data, &cek.into(), &aad)?
            }
        };

        Ok(Encrypted {
            content_algorithm: self.content_algorithm.clone(),
            key_algorithm: self.key_algorithm.clone(),
            recipients: self.recipients.clone(),
            cek: cek.to_vec(),
            iv: encrypted.iv,
            tag: encrypted.tag,
            ciphertext: encrypted.ciphertext,
        })
    }
}

impl Encrypted {
    /// Add a recipient to the encryption options.
    #[must_use]
    pub fn add_recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    pub fn finalize(self) -> Result<EncryptionProperty> {
        // encryption property
        let mut encryption = EncryptionProperty {
            algorithm: self.content_algorithm.clone(),
            initialization_vector: self.iv.clone(),
            message_authentication_code: Some(self.tag.clone()),
            key_encryption: vec![],
        };

        // add `EncryptedKey` for each recipient
        for recipient in &self.recipients {
            // recipient's public key
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

            // create `jwe::Recipient` for call to jwe key wrapping function
            let recip = jwe::Recipient {
                key_id: recipient.key_id.clone(),
                public_key: jwe::PublicKey::try_from(decoded)?,
            };
            let cek: [u8; 32] =
                self.cek.clone().try_into().map_err(|_| unexpected!("invalid CEK key"))?;

            let ke = match self.key_algorithm {
                KeyAlgorithm::EcdhEsA256Kw => jwe::ecdh_a256kw(&cek, &recip)?,
                KeyAlgorithm::EciesEs256K => jwe::ecies_es256k(&cek, &recip)?,
                KeyAlgorithm::EcdhEs => {
                    return Err(unexpected!("ECDH-ES requires a single recipient"));
                }
            };

            // unpack `jwe::KeyEncryption` into `EncryptedKey`
            let mut encrypted = EncryptedKey {
                root_key_id: recipient.key_id.clone(),
                algorithm: ke.header.alg.clone(),
                ephemeral_public_key: ke.header.epk.clone(),
                initialization_vector: ke.header.iv.clone(),
                message_authentication_code: ke.header.tag.clone(),
                cek: ke.encrypted_key.clone(),
                derivation_scheme: recipient.derivation_scheme.clone(),
                derived_public_key: None,
            };

            // attach the public key when derivation scheme is protocol-context,
            // so that the responder to this message is able to encrypt the
            // content encryption key using the same protocol-context derived
            // public key, without needing the knowledge of the corresponding
            // private key
            if recipient.derivation_scheme == DerivationScheme::ProtocolContext {
                encrypted.derived_public_key = Some(recipient.public_key.clone());
            }

            encryption.key_encryption.push(encrypted);
        }

        Ok(encryption)
    }
}

/// `EncryptionProperty` contains information about the encryption used when
/// encrypting a `Write` message. The information is used by the recipient
/// to decrypt the message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProperty {
    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `enc` property).
    pub algorithm: ContentAlgorithm,

    /// The initialization vector used to encrypt the data.
    pub initialization_vector: String,

    /// One or more objects, each containing information about the
    /// Content Encryption Key (CEK) used to encrypt the data.
    pub key_encryption: Vec<EncryptedKey>,

    /// The message authentication code.
    /// Equivalent to the JWE Authentication Tag (JWE `tag` property).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_authentication_code: Option<String>,
}

/// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
/// Encrypted Key (JWE `encrypted_key` property), this is the key used to
/// encrypt the data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id)
    /// of the root public key used to encrypt the symmetric encryption key.
    pub root_key_id: String,

    /// The derived public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_public_key: Option<PublicKeyJwk>,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,

    /// The algorithm used to encrypt the data. Equivalent to the JWE Encryption
    /// Algorithm (JWE header `alg` property).
    pub algorithm: KeyAlgorithm,

    /// The ephemeral public key used to encrypt the data.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The initialization vector used to encrypt the data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<String>,

    /// The message authentication code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_authentication_code: Option<String>,

    /// The encrypted Content Encryption Key (CEK). Equivalent to the JWE
    /// Encrypted Key (JWE `encrypted_key` property), this is the key used to
    /// encrypt the data.
    #[serde(rename = "encryptedKey")]
    pub cek: String,
}

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
        return Err(unexpected!("encryption parameter not set"));
    };
    let Some(recipient) = encryption.key_encryption.iter().find(|k| {
        k.root_key_id == ancestor_jwk.root_key_id
            && k.derivation_scheme == ancestor_jwk.derivation_scheme
    }) else {
        return Err(unexpected!("encryption key not found"));
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
        jwe::decrypt(&jwe, &receiver).await.map_err(|e| unexpected!("failed to decrypt: {e}"))?;

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
                return Err(unexpected!("`protocol` not set"));
            };
            let Some(protocol_path) = &descriptor.protocol_path else {
                return Err(unexpected!("`protocol_path` not set"));
            };

            let segments =
                protocol_path.split('/').map(ToString::to_string).collect::<Vec<String>>();
            let mut path = vec![DerivationScheme::ProtocolPath.to_string(), protocol.clone()];
            path.extend(segments);
            path
        }
        DerivationScheme::ProtocolContext => {
            let Some(context_id) = &write.context_id else {
                return Err(unexpected!("`context_id` not set"));
            };
            let segments = context_id.split('/').map(ToString::to_string).collect::<Vec<String>>();
            vec![DerivationScheme::ProtocolContext.to_string(), segments[0].clone()]
        }
        DerivationScheme::Schemas => {
            let Some(schema) = &descriptor.schema else {
                return Err(unexpected!("`schema` not set"));
            };
            vec![DerivationScheme::Schemas.to_string(), schema.clone()]
        }
    };

    Ok(derivation_path)
}

use anyhow::anyhow;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey};
use sha2::Digest;
use credibil_infosec::{SecretKey, SharedSecret};

struct ReceiverImpl(String);

impl Receiver for ReceiverImpl {
    fn key_id(&self) -> String {
        String::new()
    }

    async fn shared_secret(
        &self, sender_public: credibil_infosec::PublicKey,
    ) -> anyhow::Result<SharedSecret> {
        // EdDSA signing key
        let decoded = Base64UrlUnpadded::decode_vec(&self.0)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key = SigningKey::from_bytes(&bytes);

        // derive X25519 secret for Diffie-Hellman from Ed25519 secret
        let hash = sha2::Sha512::digest(signing_key.as_bytes());
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let secret_key = x25519_dalek::StaticSecret::from(hashed);

        let secret_key = SecretKey::from(secret_key.to_bytes());
        secret_key.shared_secret(sender_public)
    }
}
