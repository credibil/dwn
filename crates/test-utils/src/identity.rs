use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, bail};
use credibil_identity::did::{self, Document, DocumentBuilder};
use credibil_identity::{Identity as Id, Key, SignerExt};
use credibil_se::{Algorithm, Curve, PublicKey, Receiver, SharedSecret, Signer};

use crate::keystore::{KeyUse, Keyring};

pub static DID_STORE: LazyLock<Arc<Mutex<HashMap<String, Document>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Clone)]
pub struct Identity {
    pub url: String,
    did: String,
    keyring: Keyring,
    invalid: bool,
}

impl Identity {
    // Generate a DID-based Identity.
    pub async fn new(owner: &str) -> Self {
        // create a new keyring and add a signing key.
        let mut keyring = Keyring::new(owner).await.expect("keyring created");
        keyring.add("signer", KeyUse::Signing).await.expect("signing key added");
        let verifying_key =
            keyring.verifying_key_jwk("signer").await.expect("JWK verifying key derived");

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

    pub async fn invalid() -> Self {
        let mut id = Self::new("invalid").await;
        id.invalid = true;
        id.keyring.keys.add(&Curve::Ed25519, "bad_signer").await.expect("bad signing key");
        id
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub async fn public_key(&self) -> Result<Vec<u8>> {
        self.keyring.verifying_key("signer").await
    }

    pub async fn resolve(&self, url: &str) -> Result<Id> {
        let key = url.trim_end_matches("/did.json");
        let store = DID_STORE.lock().expect("should lock");
        let Some(doc) = store.get(key).cloned() else {
            bail!("document not found");
        };
        Ok(Id::DidDocument(doc))
    }
}

impl Signer for Identity {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.invalid {
            self.keyring.sign("bad_signer", msg).await
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
        let Id::DidDocument(doc) = self.resolve(&self.url).await?;
        let vm = &doc.verification_method.as_ref().unwrap()[0];
        Ok(Key::KeyId(vm.id.clone()))
    }
}

impl Receiver for Identity {
    async fn key_id(&self) -> Result<String> {
        Ok(self.did.clone())
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        let secret = self.keyring.keys.private_key("signing").await?;
        credibil_se::derive_x25519_secret(secret.as_bytes(), &sender_public)
    }
}
