use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SecretKey, Signer, SigningKey};
use vercre_infosec::{Algorithm, Curve, KeyType, PublicKeyJwk};

pub const OWNER_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
pub const OWNER_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
pub const OWNER_SECRET_KEY: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

#[derive(Default, Clone, Debug)]
pub struct Keystore;

impl Keystore {
    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(OWNER_SECRET_KEY)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    pub fn public_key() -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(OWNER_SECRET_KEY)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    pub fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    pub async fn verification_method() -> Result<String> {
        Ok(format!("{OWNER_DID}#{OWNER_VERIFY_KEY}"))
    }

    pub fn public_jwk() -> PublicKeyJwk {
        let (_, key_bytes) = multibase::decode(OWNER_VERIFY_KEY).expect("should decode");
        if key_bytes.len() - 2 != 32 {
            panic!("key is not 32 bytes long");
        }
        if key_bytes[0..2] != ED25519_CODEC {
            panic!("not Ed25519");
        }

        PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
            ..PublicKeyJwk::default()
        }
    }
}
