//! # Keystore

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signer as _, SigningKey};
use sha2::Digest;
use vercre_infosec::{Algorithm, PublicKey, Receiver, SecretKey, SharedSecret, Signer};

pub const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
pub const ALICE_VERIFYING_KEY: &str = "RW-Q0fO2oECyLs4rZDZZo4p6b7pu7UF2eu9JBsktDco";
const ALICE_SECRET_KEY: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

pub const BOB_DID: &str = "did:key:z6MkqWGVUwMwt4ahxESTVg1gjvxZ4w4KkXomksSMdCB3eHeD";
pub const BOB_VERIFYING_KEY: &str = "pDXNqUD-tOc2LolwWFOKTwNSMtUqkdLJy9dG3sXe0ZY";
const BOB_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

pub const CAROL_DID: &str = "did:key:z6MkuY2MjELw3xQExptJtVkuW5YSjfeQYrVZv41RMYrwZmYd";
pub const CAROL_VERIFYING_KEY: &str = "4Be7T4GDYNqXtdUIRSR4fcYEb-T3NV06uQJ-gSJA0xo";
const CAROL_SECRET_KEY: &str = "V0YsmES1Tc8-sozoyYeBKemcrUaOLq_IceWbjWwmbMo";

pub const APP_DID: &str = "did:key:z6MkmR9wAW5BP3RoG8NMDRsw9DRxVYXjPNm3rqJtAQY3yfrH";
pub const APP_VERIFYING_KEY: &str = "1mFX9lH0IiwfHh0Oeq9JL4rbm-kkbKFylQZygKXEtTI";
const APP_SECRET_KEY: &str = "M5In2tCAa1xiK9HRJRz8wXgWOtaWPMVegIVW24rCf_E";

pub const INVALID_DID: &str = "did:key:z6Mkj85hWKz3rvxVt6gL54rCsEMia8ZRXMTmxaUv4yLDSnTA";
const INVALID_SECRET_KEY: &str = "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo";

pub fn signer(did: &str) -> impl Signer {
    keyring(did)
}

pub fn receiver(did: &str) -> impl Receiver {
    keyring(did)
}

fn keyring(did: &str) -> impl Signer + Receiver {
    match did {
        ALICE_DID => Keyring {
            did: ALICE_DID.to_string(),
            secret_key: ALICE_SECRET_KEY.to_string(),
        },
        BOB_DID => Keyring {
            did: BOB_DID.to_string(),
            secret_key: BOB_SECRET_KEY.to_string(),
        },
        CAROL_DID => Keyring {
            did: CAROL_DID.to_string(),
            secret_key: CAROL_SECRET_KEY.to_string(),
        },
        APP_DID => Keyring {
            did: APP_DID.to_string(),
            secret_key: APP_SECRET_KEY.to_string(),
        },
        INVALID_DID => Keyring {
            did: INVALID_DID.to_string(),
            secret_key: INVALID_SECRET_KEY.to_string(),
        },
        _ => panic!("Unknown DID"),
    }
}

#[derive(Default, Clone, Debug)]
pub struct Keyring {
    pub did: String,
    pub secret_key: String,
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

    async fn verification_method(&self) -> Result<String> {
        let verify_key = self.did.strip_prefix("did:key:").unwrap_or_default();
        Ok(format!("{}#{}", self.did, verify_key))
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

        // derive X25519 secret for Diffie-Hellman from Ed25519 secret
        let hash = sha2::Sha512::digest(signing_key.as_bytes());
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let secret_key = x25519_dalek::StaticSecret::from(hashed);

        let secret_key = SecretKey::from(secret_key.to_bytes());
        secret_key.shared_secret(sender_public)
    }
}
