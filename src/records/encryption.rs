use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use vercre_infosec::jose::jwe::{
    self, ContentAlgorithm, Header, JweBuilder, KeyAlgorithm, KeyEncryption, Protected, PublicKey,
    Recipients,
};
use vercre_infosec::jose::{Curve, Jwe, PublicKeyJwk};

use crate::hd_key::{DerivationScheme, DerivedPrivateJwk};
use crate::records::Write;
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
#[allow(clippy::struct_field_names)]
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
    pub encrypted_key: String,
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

            builder = builder.add_recipient(&recipient.key_id, PublicKey::from_slice(&decoded)?);
        }

        let jwe = builder.build()?;
        println!("JWE: {jwe:?}\n");

        // use JWE to build EncryptionProperty
        let mut encryption = EncryptionProperty {
            algorithm: jwe.protected.enc.clone(),
            initialization_vector: jwe.iv.clone(),
            message_authentication_code: Some(jwe.tag.clone()),
            key_encryption: vec![],
        };

        // extract fields from JWE
        let key_encryptions = match &jwe.recipients {
            Recipients::One(recipient) => vec![recipient.clone()],
            Recipients::Many { recipients } => recipients.clone(),
        };

        for (i, key_encryption) in key_encryptions.iter().enumerate() {
            let key_input = &self.recipients[i];

            let header = &key_encryption.header;
            let Some(key_id) = header.kid.clone() else {
                return Err(unexpected!("missing key id"));
            };

            let mut encrypted = EncryptedKey {
                root_key_id: key_id,
                algorithm: header.alg.clone(),
                ephemeral_public_key: header.epk.clone(),
                initialization_vector: header.iv.clone(),
                message_authentication_code: header.tag.clone(),
                encrypted_key: key_encryption.encrypted_key.clone(),
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

/// Decrypt the provided data using the encryption properties specified in the
/// `Write` message.
///
/// # Errors
/// LATER: Add error handling
pub async fn decrypt(
    data: &[u8], write: &Write, ancestor_jwk: &DerivedPrivateJwk,
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

    // let derivation_path= derivation_path(recipient, write)?;
    // let derived_jwk = hd_key::derive_jwk(ancestor_jwk.clone(), &derivation_path)?;
    // let receiver = ReceiverImpl(derived_jwk.derived_private_key.d.clone());
    let receiver = ReceiverImpl(ancestor_jwk.derived_private_key.d.clone());

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
            encrypted_key: recipient.encrypted_key.clone(),
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

#[allow(dead_code)]
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
use vercre_infosec::{Receiver, SecretKey, SharedSecret};

struct ReceiverImpl(String);

impl Receiver for ReceiverImpl {
    fn key_id(&self) -> String {
        String::new()
    }

    async fn shared_secret(
        &self, sender_public: vercre_infosec::PublicKey,
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
