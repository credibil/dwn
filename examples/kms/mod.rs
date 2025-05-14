#![allow(missing_docs, dead_code)]

//! # Keystore

use credibil_identity::{Key, SignerExt};
use credibil_se::{
    Algorithm, Curve, ED25519_CODEC, PublicKey, Receiver, SharedSecret, Signer,
    derive_x25519_secret,
};
use multibase::Base;
use test_kms::Keyring as BaseKeyring;

#[derive(Clone)]
pub struct Keyring {
    // The owner of the keyring.
    pub owner: String,

    // Underlying key store.
    keys: BaseKeyring,

    // Set to true to sign with a private key that does not match the
    // verifying key to test verification is catching bad signatures.
    pub bad_signing: bool,
}

impl Keyring {
    pub async fn new(owner: &str) -> anyhow::Result<Self> {
        let mut keys = BaseKeyring::new(owner).await?;
        keys.add(&Curve::Ed25519, "signing").await?;


        Ok(Keyring { owner: owner.to_string(), keys, bad_signing: false })
    }

    pub async fn did(&self) -> anyhow::Result<String> {
        let verifying_key = self.keys.verifying_key("signing").await?;
        let mut multi_bytes = ED25519_CODEC.to_vec();
        multi_bytes.extend_from_slice(&verifying_key);
        let verifying_multi = multibase::encode(Base::Base58Btc, &multi_bytes);
        Ok(format!("did:key:{verifying_multi}"))
    }

    pub async fn public_key(&self) -> anyhow::Result<PublicKey> {
        self.keys.public_key("signing").await
    }

    pub async fn replace(&mut self, key: &str) -> anyhow::Result<()> {
        self.keys.replace(key).await
    }

    // Sign with a private key that does not match the verifying key to test
    // verification is catching bad signatures.
    async fn bad_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut bad_keyring = BaseKeyring::new(&self.owner).await?;
        bad_keyring.add_or_replace(&Curve::Ed25519, "bad_signing").await?;
        bad_keyring.sign("bad_signing", msg).await
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.bad_signing {
            return self.bad_sign(msg).await
        }
        self.keys.sign("signing", msg).await
    }

    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        self.keys.verifying_key("signing").await
    }

    async fn algorithm(&self) -> anyhow::Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl SignerExt for Keyring {
    async fn verification_method(&self) -> anyhow::Result<Key> {
        let did = self.did().await?;
        let verify_key = did.strip_prefix("did:key:").unwrap_or_default();
        Ok(Key::KeyId(format!("{}#{}", did, verify_key)))
    }
}

impl Receiver for Keyring {
    async fn key_id(&self) -> anyhow::Result<String> {
        self.did().await
    }

    // As we're using `did:key`, we only have a single private key for EdDSA
    // signing and X25519 ECDH. We can derive an X25519 secret from the Ed25519
    // signing key.
    async fn shared_secret(&self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
        let secret = self.keys.private_key("signing").await?;
        derive_x25519_secret(secret.as_bytes(), &sender_public)
    }
}
