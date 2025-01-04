//! # Keystore

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signer as _, SigningKey};
use sha2::Digest;
use vercre_dwn::provider::{KeyStore, Keyring};
use vercre_infosec::{Algorithm, PublicKey, Receiver, SecretKey, SharedSecret, Signer};

// use x25519_dalek::{PublicKey, StaticSecret};
use crate::provider::ProviderImpl;

pub const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
pub const ALICE_VERIFYING_KEY: &str = "RW-Q0fO2oECyLs4rZDZZo4p6b7pu7UF2eu9JBsktDco";
const ALICE_SECRET_KEY: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

pub const BOB_DID: &str = "did:key:z6MkqWGVUwMwt4ahxESTVg1gjvxZ4w4KkXomksSMdCB3eHeD";
pub const BOB_VERIFYING_KEY: &str = "pDXNqUD-tOc2LolwWFOKTwNSMtUqkdLJy9dG3sXe0ZY";
const BOB_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

pub const CAROL_DID: &str = "did:key:z6MkuY2MjELw3xQExptJtVkuW5YSjfeQYrVZv41RMYrwZmYd";
pub const CAROL_VERIFYING_KEY: &str = "4Be7T4GDYNqXtdUIRSR4fcYEb-T3NV06uQJ-gSJA0xo";
const CAROL_SECRET_KEY: &str = "V0YsmES1Tc8-sozoyYeBKemcrUaOLq_IceWbjWwmbMo";

pub const APP_DID: &str = "did:key:z6Mkj85hWKz3rvxVt6gL54rCsEMia8ZRXMTmxaUv4yLDSnTA";
const APP_SECRET_KEY: &str = "fAe8yt4xBaDpyuPKY9_1NBxmiFMCfVnnryMXD-oLyVk";

pub const INVALID_DID: &str = "did:key:z6Mkj85hWKz3rvxVt6gL54rCsEMia8ZRXMTmxaUv4yLDSnTA";
const INVALID_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

#[derive(Default, Clone, Debug)]
pub struct KeyStoreImpl {
    keyrings: HashMap<String, KeyringImpl>,
}

#[derive(Default, Clone, Debug)]
pub struct KeyringImpl {
    pub did: String,
    pub secret_key: String,
}

impl KeyStoreImpl {
    // Populate the keystore with test keyrings
    pub fn new() -> Self {
        let mut keyrings = HashMap::new();

        let alice_keyring = KeyringImpl {
            did: ALICE_DID.to_string(),
            secret_key: ALICE_SECRET_KEY.to_string(),
        };
        let bob_keyring = KeyringImpl {
            did: BOB_DID.to_string(),
            secret_key: BOB_SECRET_KEY.to_string(),
        };
        let carol_keyring = KeyringImpl {
            did: CAROL_DID.to_string(),
            secret_key: CAROL_SECRET_KEY.to_string(),
        };
        let app_keyring = KeyringImpl {
            did: APP_DID.to_string(),
            secret_key: APP_SECRET_KEY.to_string(),
        };
        let invalid_keyring = KeyringImpl {
            did: INVALID_DID.to_string(),
            secret_key: INVALID_SECRET_KEY.to_string(),
        };

        keyrings.insert(ALICE_DID.to_string(), alice_keyring);
        keyrings.insert(BOB_DID.to_string(), bob_keyring);
        keyrings.insert(CAROL_DID.to_string(), carol_keyring);
        keyrings.insert(APP_DID.to_string(), app_keyring);
        keyrings.insert(INVALID_DID.to_string(), invalid_keyring);

        Self { keyrings }
    }
}

impl KeyStore for ProviderImpl {
    fn keyring(&self, identifier: &str) -> Result<impl Keyring> {
        self.keystore.keyrings.get(identifier).cloned().ok_or_else(|| anyhow!("keyring not found"))
    }
}

impl Keyring for KeyringImpl {}

impl Signer for KeyringImpl {
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

    async fn verification_method(&self) -> Result<String> {
        let verify_key = self.did.strip_prefix("did:key:").unwrap_or_default();
        Ok(format!("{}#{}", self.did, verify_key))
    }
}

impl Receiver for KeyringImpl {
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

        // derive X25519 secret for Diffie-Hellman from Ed25519 secret
        let hash = sha2::Sha512::digest(signing_key.as_bytes());
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let secret_key = x25519_dalek::StaticSecret::from(hashed);

        let secret_key = SecretKey::from(secret_key.to_bytes());
        secret_key.shared_secret(sender_public)
    }
}
