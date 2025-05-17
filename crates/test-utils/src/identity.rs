use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, bail};
use credibil_identity::did::{self, Document, DocumentBuilder};
use credibil_identity::{Key, SignerExt};
use credibil_jose::PublicKeyJwk;
use credibil_se::{Algorithm, Curve, PublicKey, Receiver, SharedSecret, Signer};

pub static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct Identity {
    pub url: String,
    did: String,
    keyring: test_kms::Keyring,
    invalid: bool,
}

impl Identity {
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = test_kms::Keyring::new(owner).await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "signer").await.expect("keyring created");
        let key_bytes = keyring.verifying_key("signer").await.expect("key bytes");
        let verifying_key = PublicKeyJwk::from_bytes(&key_bytes).expect("verifying key");

        // generate a did:web document
        let url = format!("https://credibil.io/{}", uuid::Uuid::new_v4());
        let did = did::web::default_did(&url).expect("should construct DID");

        let document = DocumentBuilder::new(&did)
            .add_verifying_key(&verifying_key, true)
            .expect("should add verifying key")
            .build();
        DID_STORE.lock().expect("should lock").insert(url.clone(), document);

        Self {
            url,
            did,
            keyring,
            invalid: false,
        }
    }

    pub async fn invalid(owner: &str) -> Self {
        let mut id = Self::new(owner).await;
        id.invalid = true;
        id
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub async fn public_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key("signer").await
    }
}

impl Signer for Identity {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.invalid {
            let mut keyring = test_kms::Keyring::new("random").await?;
            keyring.add(&Curve::Ed25519, "signer").await?;
            keyring.sign("signer", msg).await
        } else {
            self.keyring.sign("signer", msg).await
        }
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key("signer").await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl SignerExt for Identity {
    async fn verification_method(&self) -> Result<Key> {
        let store = DID_STORE.lock().expect("should lock");
        let Some(doc) = store.get(&self.url).cloned() else {
            bail!("document not found");
        };
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }
}

impl Receiver for Identity {
    async fn key_id(&self) -> Result<String> {
        Ok(self.did.clone())
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        let secret = self.keyring.private_key("signing").await?;
        credibil_se::derive_x25519_secret(secret.as_bytes(), &sender_public)
    }
}
