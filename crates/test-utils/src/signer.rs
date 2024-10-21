use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SecretKey, Signer, SigningKey};
// use vercre_infosec::jose::jwa::Algorithm;

pub const OWNER_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
pub const OWNER_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const OWNER_SECRET: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
    let decoded = Base64UrlUnpadded::decode_vec(OWNER_SECRET)?;
    let secret_key: SecretKey = decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

    Ok(signing_key.sign(msg).to_bytes().to_vec())
}
