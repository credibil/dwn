use anyhow::Result;
use credibil_ecc::Curve::Ed25519;
use credibil_ecc::{Algorithm, Entry, Keyring, PublicKey, Receiver, SharedSecret, Signer};
use credibil_jose::PublicKeyJwk;
use credibil_proof::did::{Document, DocumentBuilder, KeyId, VerificationMethod};
use credibil_proof::{Signature, VerifyBy};

use crate::datastore::Store;
use crate::vault::KeyVault as Vault;

#[derive(Clone)]
pub struct Identity {
    document: Document,
    signer: Entry,
    invalid: bool,
}

impl Identity {
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let signer =
            Keyring::generate(&Vault, owner, "signing", Ed25519).await.expect("should generate");
        let key = signer.verifying_key().await.expect("key bytes");
        let jwk = PublicKeyJwk::from_bytes(&key.to_bytes()).expect("verifying key");

        // generate (and store) a did:web document
        let url = format!("https://credibil.io/{}", uuid::Uuid::new_v4());
        let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
        let builder = DocumentBuilder::new().verification_method(vm).derive_key_agreement(true);
        let document = credibil_proof::create(&url, builder, &Store).await.expect("should create");

        Self {
            document,
            signer,
            invalid: false,
        }
    }

    pub async fn invalid(owner: &str) -> Self {
        let mut id = Self::new(owner).await;
        id.invalid = true;
        id
    }

    pub fn did(&self) -> &str {
        &self.document.id
    }

    pub async fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.signer.verifying_key().await?.to_bytes().to_vec())
    }
}

impl Signer for Identity {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.invalid {
            let signer = Keyring::generate(&Vault, "random", "signing", Ed25519).await?;
            Ok(signer.sign(msg).await)
        } else {
            Ok(self.signer.sign(msg).await)
        }
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        self.signer.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for Identity {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let vm = &self.document.verification_method.as_ref().unwrap()[0];
        Ok(VerifyBy::KeyId(vm.id.clone()))
    }
}

impl Receiver for Identity {
    async fn key_id(&self) -> Result<String> {
        Ok(self.document.id.clone())
    }

    async fn public_key(&self) -> Result<PublicKey> {
        self.signer.verifying_key().await
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        self.signer.shared_secret(sender_public).await
    }
}
