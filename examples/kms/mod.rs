#![allow(missing_docs, dead_code)]

//! # Keystore

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::SignerExt;
use credibil_infosec::{jose::jws::Key, Algorithm, PublicKey, Receiver, SecretKey, SharedSecret, Signer};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signer as _, SigningKey};
use multibase::Base;
use rand::rngs::OsRng;
use sha2::Digest;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

#[derive(Default, Clone, Debug)]
pub struct Keyring {
    pub did: String,
    public_key: String,
    pub secret_key: String,
}

impl Keyring {
    pub fn new() -> Keyring {
        let signing_key = SigningKey::generate(&mut OsRng);

        // verifying key (Ed25519)
        let verifying_key = signing_key.verifying_key();
        let mut multi_bytes = ED25519_CODEC.to_vec();
        multi_bytes.extend_from_slice(&verifying_key.to_bytes());
        let verifying_multi = multibase::encode(Base::Base58Btc, &multi_bytes);

        // public key (X25519)
        let public_key = verifying_key.to_montgomery();

        Keyring {
            did: format!("did:key:{verifying_multi}"),
            public_key: Base64UrlUnpadded::encode_string(public_key.as_bytes()),
            secret_key: Base64UrlUnpadded::encode_string(signing_key.as_bytes()),
        }
    }

    pub fn did(&self) -> String {
        self.did.clone()
    }

    pub fn public_key(&self) -> x25519_dalek::PublicKey {
        let public_bytes: [u8; 32] =
            Base64UrlUnpadded::decode_vec(&self.public_key).unwrap().try_into().unwrap();
        x25519_dalek::PublicKey::from(public_bytes)
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: ed25519_dalek::SecretKey =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: ed25519_dalek::SecretKey =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

impl SignerExt for Keyring {
    async fn verification_method(&self) -> Result<Key> {
        let verify_key = self.did.strip_prefix("did:key:").unwrap_or_default();
        Ok(Key::KeyId(format!("{}#{}", self.did, verify_key)))
    }
}

impl Receiver for Keyring {
    fn key_id(&self) -> String {
        self.did.clone()
    }

    // As we're using `did:key`, we only have a single private key for EdDSA
    // signing and X25519 ECDH. We can derive an X25519 secret from the Ed25519
    // signing key.
    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        // EdDSA signing key
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key = SigningKey::from_bytes(&bytes);

        // *** derive X25519 secret for Diffie-Hellman from Ed25519 secret ***
        let hash = sha2::Sha512::digest(signing_key.as_bytes());
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let secret_key = x25519_dalek::StaticSecret::from(hashed);

        let secret_key = SecretKey::from(secret_key.to_bytes());
        secret_key.shared_secret(sender_public)
    }
}
