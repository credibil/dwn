use credibil_jose::PublicKeyJwk;
use credibil_se::Curve;
use test_kms::Keyring as BaseKeyring;

#[derive(Clone)]
pub struct Keyring {
    pub keys: BaseKeyring,
}

impl Keyring {
    pub async fn new(owner: &str) -> anyhow::Result<Self> {
        Ok(Self {
            keys: BaseKeyring::new(owner).await?,
        })
    }

    pub async fn add(&mut self, key_id: impl Into<String>, key: KeyUse) -> anyhow::Result<()> {
        let curve = match key {
            KeyUse::Signing => Curve::Ed25519,
            // KeyUse::Encryption => Curve::X25519,
        };
        self.keys.add(&curve, key_id.into()).await
    }

    pub async fn verifying_key_jwk(
        &self, key_id: impl Into<String>,
    ) -> anyhow::Result<PublicKeyJwk> {
        let key = self.keys.verifying_key(key_id.into()).await?;
        PublicKeyJwk::from_bytes(&key)
    }

    pub async fn verifying_key(&self, key_id: impl Into<String>) -> anyhow::Result<Vec<u8>> {
        self.keys.verifying_key(key_id.into()).await
    }

    pub async fn sign(&self, key_id: impl Into<String>, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.keys.sign(key_id.into(), msg).await
    }
}

#[derive(Clone)]
pub enum KeyUse {
    Signing,
    // Encryption,
}
