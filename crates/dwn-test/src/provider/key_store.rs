//! # Keystore

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer as _, SigningKey};
use vercre_dwn::provider::{KeyStore, Keyring};
use vercre_infosec::{Algorithm, PublicKey, Receiver, SecretKey, SharedSecret, Signer};

// use x25519_dalek::{PublicKey, StaticSecret};
use crate::provider::ProviderImpl;

pub const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const ALICE_SECRET_KEY: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

pub const BOB_DID: &str = "did:key:z6MkqWGVUwMwt4ahxESTVg1gjvxZ4w4KkXomksSMdCB3eHeD";
const BOB_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

pub const CAROL_DID: &str = "did:key:z6MkuY2MjELw3xQExptJtVkuW5YSjfeQYrVZv41RMYrwZmYd";
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

    async fn public_key(&self) -> Result<Vec<u8>> {
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
    // // FIXME: wrap return in Result<Vec<u8>>
    // fn public_key(&self) -> Vec<u8> {
    //     let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key).unwrap();
    //     let bytes: [u8; 32] =
    //         decoded.try_into().map_err(|_| anyhow!("Invalid secret key")).unwrap();

    //     // derive x25519 key agreement public key
    //     PublicKey::from(bytes).as_bytes().to_vec()
    // }

    fn key_id(&self) -> String {
        self.did.clone()
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;

        let secret_key = SecretKey::from(bytes);
        secret_key.shared_secret(sender_public)
    }
}
