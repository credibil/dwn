#![allow(missing_docs)]
#![allow(unused_variables)]

//! # Provider
//!
//! Implementation of the `Provider` trait for testing and examples.

pub mod data;
pub mod event;
pub mod message;
pub mod task;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use surrealdb::engine::local::{Db, Mem};
use surrealdb::opt::RecordId;
use surrealdb::Surreal;
use vercre_dwn::protocols::Configure;
use vercre_dwn::provider::{DidResolver, Document, KeyStore, Keyring, Provider};
use vercre_infosec::{Algorithm, Cipher, Signer};

use crate::keystore::{Keystore, OWNER_DID};

const NAMESPACE: &str = "integration-test";
const MESSAGE: &str = "message";
const DATA: &str = "data";

#[derive(Clone)]
pub struct ProviderImpl {
    db: Surreal<Db>,
}

impl Provider for ProviderImpl {}

impl ProviderImpl {
    pub async fn new() -> Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns(NAMESPACE).use_db(OWNER_DID).await?;

        let bytes = include_bytes!("./store/protocol.json");
        let config: Configure = serde_json::from_slice(bytes).expect("should deserialize");
        let _: Vec<Record> = db.create(MESSAGE).content(config).await.expect("should create");

        Ok(Self { db })
    }
}

#[derive(Debug, Deserialize)]
struct Record {
    #[allow(dead_code)]
    id: RecordId,
}

impl DidResolver for ProviderImpl {
    async fn resolve(&self, url: &str) -> Result<Document> {
        serde_json::from_slice(include_bytes!("./store/did.json"))
            .map_err(|e| anyhow!("issue deserializing document: {e}"))
    }
}

struct KeyStoreImpl(Keystore);

impl KeyStore for ProviderImpl {
    fn keyring(&self, _identifier: &str) -> anyhow::Result<impl Keyring> {
        Ok(KeyStoreImpl(Keystore {}))
    }

    // fn signer(&self, _identifier: &str) -> anyhow::Result<impl Signer> {
    //     Ok(KeyStoreImpl(Keystore {}))
    // }

    // fn cipher(&self, _identifier: &str) -> anyhow::Result<impl Cipher> {
    //     Ok(KeyStoreImpl(Keystore {}))
    // }
}

impl Keyring for KeyStoreImpl {}

impl Signer for KeyStoreImpl {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Keystore::try_sign(msg)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        Keystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        Keystore::algorithm()
    }

    fn verification_method(&self) -> String {
        Keystore::verification_method()
    }
}

impl Cipher for KeyStoreImpl {
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
