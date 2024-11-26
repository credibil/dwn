//! # Keystore

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SecretKey, Signer as _, SigningKey};
use vercre_dwn::provider::{KeyStore, Keyring};
use vercre_infosec::{Algorithm, Cipher, Signer};

use crate::store::ProviderImpl;

pub const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const ALICE_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const ALICE_SECRET_KEY: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

pub const BOB_DID: &str = "did:key:z6MkqWGVUwMwt4ahxESTVg1gjvxZ4w4KkXomksSMdCB3eHeD";
const BOB_VERIFY_KEY: &str = "z6MkqWGVUwMwt4ahxESTVg1gjvxZ4w4KkXomksSMdCB3eHeD";
const BOB_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

pub const APP_DID: &str = "did:key:z6Mkj85hWKz3rvxVt6gL54rCsEMia8ZRXMTmxaUv4yLDSnTA";
const APP_VERIFY_KEY: &str = "z6Mkj85hWKz3rvxVt6gL54rCsEMia8ZRXMTmxaUv4yLDSnTA";
const APP_SECRET_KEY: &str = "fAe8yt4xBaDpyuPKY9_1NBxmiFMCfVnnryMXD-oLyVk";

// const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

#[derive(Default, Clone, Debug)]
pub struct KeystoreImpl {
    keyrings: HashMap<String, KeyringImpl>,
}

#[derive(Default, Clone, Debug)]
pub struct KeyringImpl {
    pub did: String,
    pub verify_key: String,
    pub secret_key: String,
}

impl KeystoreImpl {
    // Populate the keystore with test keyrings
    pub fn new() -> Self {
        let mut keyrings = HashMap::new();

        let alice_keyring = KeyringImpl {
            did: ALICE_DID.to_string(),
            verify_key: ALICE_VERIFY_KEY.to_string(),
            secret_key: ALICE_SECRET_KEY.to_string(),
        };
        let bob_keyring = KeyringImpl {
            did: BOB_DID.to_string(),
            verify_key: BOB_VERIFY_KEY.to_string(),
            secret_key: BOB_SECRET_KEY.to_string(),
        };
        let app_keyring = KeyringImpl {
            did: APP_DID.to_string(),
            verify_key: APP_VERIFY_KEY.to_string(),
            secret_key: APP_SECRET_KEY.to_string(),
        };

        keyrings.insert(ALICE_DID.to_string(), alice_keyring);
        keyrings.insert(BOB_DID.to_string(), bob_keyring);
        keyrings.insert(APP_DID.to_string(), app_keyring);

        Self { keyrings }
    }
}

impl KeyStore for ProviderImpl {
    fn keyring(&self, identifier: &str) -> Result<impl Keyring> {
        self.keystore.keyrings.get(identifier).cloned().ok_or_else(|| anyhow!("Keyring not found"))
    }
}

impl Keyring for KeyringImpl {}

impl Signer for KeyringImpl {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    async fn verification_method(&self) -> Result<String> {
        Ok(format!("{}#{}", self.did, self.verify_key))
    }
}

impl Cipher for KeyringImpl {
    async fn encrypt(&self, _plaintext: &[u8], _recipient_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn ephemeral_public_key(&self) -> Vec<u8> {
        todo!()
    }

    async fn decrypt(&self, _ciphertext: &[u8], _sender_public_key: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}

// #[derive(Default, Clone, Debug)]
// pub struct Keystore;

// impl Keystore {
//     pub fn try_sign(&self, _msg: &[u8]) -> Result<Vec<u8>> {
//         unimplemented!()
//     }

//     pub fn public_key(&self) -> Result<Vec<u8>> {
//         unimplemented!()
//     }

//     pub fn algorithm(&self) -> Algorithm {
//         Algorithm::EdDSA
//     }

//     pub async fn verification_method(&self) -> Result<String> {
//         unimplemented!()
//     }

//     pub fn public_jwk(&self) -> PublicKeyJwk {
//         unimplemented!()

//         // let (_, key_bytes) = multibase::decode(OWNER_VERIFY_KEY).expect("should decode");
//         // if key_bytes.len() - 2 != 32 {
//         //     panic!("key is not 32 bytes long");
//         // }
//         // if key_bytes[0..2] != ED25519_CODEC {
//         //     panic!("not Ed25519");
//         // }

//         // PublicKeyJwk {
//         //     kty: KeyType::Okp,
//         //     crv: Curve::Ed25519,
//         //     x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
//         //     ..PublicKeyJwk::default()
//         // }
//     }
// }
