//! Data record handling.

use std::io::{self, Read, Write};
use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use libipld::block::Block;
use libipld::cbor::DagCborCodec;
use libipld::cid::multihash::Code;
use libipld::ipld::Ipld;
use libipld::store::DefaultParams;
use serde::{Deserialize, Serialize};

use crate::provider::BlockStore;
use crate::{Result, unexpected};

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 30000;

const CHUNK_SIZE: usize = 16;

/// Compute CID from a data value or stream.
pub mod cid {
    use cid::Cid;
    use multihash_codetable::MultihashDigest;
    use serde::Serialize;

    use crate::Result;

    const RAW: u64 = 0x55;

    /// Compute a CID from provided payload, serialized to CBOR.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn from_value<T: Serialize>(payload: &T) -> Result<String> {
        let mut buf = Vec::new();
        ciborium::into_writer(payload, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash).to_string())
    }
}

/// Data stream for serializing/deserializing web node data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DataStream {
    /// The data to be read.
    pub buffer: Vec<u8>,

    /// The encryption settings.
    pub encryption: Option<EncryptionProperty>,
}

impl DataStream {
    /// Create a new `DataStream`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DataStream {
    /// Compute a CID for the provided data stream.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn compute_cid(&self) -> Result<(String, usize)> {
        let mut cid = self.clone();

        let mut links = vec![];
        let mut byte_count = 0;

        loop {
            let mut buffer = [0u8; CHUNK_SIZE];
            if let Ok(bytes_read) = cid.read(&mut buffer[..]) {
                if bytes_read == 0 {
                    break;
                }

                let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
                let block = Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &ipld)?;
                let cid = block.cid();

                // save block's CID as a link
                links.push(Ipld::Link(*cid));
                byte_count += bytes_read;
            }
        }

        let block =
            Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &Ipld::List(links))?;
        let cid = &block.cid();

        Ok((cid.to_string(), byte_count))
    }

    /// Write data stream to the underlying block store.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn to_store(
        &mut self, owner: &str, store: &impl BlockStore,
    ) -> Result<(String, usize)> {
        let mut links = vec![];
        let mut byte_count = 0;

        // read data stream in chunks, storing each chunk as an IPLD block
        loop {
            let mut buffer = [0u8; CHUNK_SIZE];
            if let Ok(bytes_read) = self.read(&mut buffer[..]) {
                if bytes_read == 0 {
                    break;
                }
                // encode buffer to IPLD block
                let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
                let block = Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &ipld)?;

                // insert into the blockstore
                let cid = block.cid();
                store.put(owner, &cid.to_string(), block.data()).await?;

                // save link to block
                links.push(Ipld::Link(*cid));
                byte_count += bytes_read;
            }
        }

        // create a root block linking to the data blocks
        let block =
            Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &Ipld::List(links))?;
        let cid = &block.cid();
        store.put(owner, &cid.to_string(), block.data()).await?;

        Ok((cid.to_string(), byte_count))
    }

    /// Read data stream from the underlying block store.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn from_store(
        owner: &str, cid: &str, store: &impl BlockStore,
    ) -> Result<Option<Self>> {
        // get root block
        let Some(bytes) = store.get(owner, cid).await? else {
            return Ok(None);
        };
        let cid = libipld::Cid::from_str(cid)?;
        let block = Block::<DefaultParams>::new(cid, bytes)?;
        let ipld = block.decode::<DagCborCodec, Ipld>()?;

        // the root blook contains a list of links to data blocks
        let Ipld::List(links) = ipld else {
            return Ok(None);
        };

        // fetch each data block
        let mut data_stream = Self::new();
        for link in links {
            let Ipld::Link(link_cid) = link else {
                return Err(unexpected!("invalid link"));
            };

            // get data block
            let Some(bytes) = store.get(owner, &link_cid.to_string()).await? else {
                return Ok(None);
            };
            let block = Block::<DefaultParams>::new(link_cid, bytes)?;

            // get data block's payload
            let ipld = block.decode::<DagCborCodec, Ipld>()?;
            let Ipld::Bytes(bytes) = ipld else {
                return Ok(None);
            };

            data_stream.write_all(&bytes)?;
        }

        Ok(Some(data_stream))
    }
}

impl From<Vec<u8>> for DataStream {
    fn from(data: Vec<u8>) -> Self {
        Self {
            buffer: data,
            encryption: None,
        }
    }
}

impl From<&[u8]> for DataStream {
    fn from(data: &[u8]) -> Self {
        Self {
            buffer: data.to_vec(),
            encryption: None,
        }
    }
}

impl Read for DataStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = std::cmp::min(buf.len(), self.buffer.len());
        buf[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer = self.buffer[n..].to_vec();
        Ok(n)
    }
}

impl Write for DataStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

use vercre_infosec::jose::jwe::{
    ContentAlgorithm, JweBuilder, KeyAlgorithm, PublicKey, Recipients,
};
use vercre_infosec::jose::{Curve, PublicKeyJwk};

use crate::hd_key::DerivationScheme;
use crate::records::write::{EncryptedKey, EncryptionProperty};

impl DataStream {
    /// Encrypt the data stream using the provided encryption settings.
    ///
    /// Resultant encryption output parameters are temporarily stored in the
    /// `DataStream` object.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn encrypt(mut self, config: &Encryption) -> Result<Self> {
        // build JWE
        let mut builder = JweBuilder::new()
            .content_algorithm(ContentAlgorithm::A256Gcm)
            .key_algorithm(KeyAlgorithm::EcdhEsA256Kw)
            .payload(&self.buffer);

        for recipient in &config.recipients {
            let jwk = &recipient.public_key;
            let decoded = if jwk.crv == Curve::Ed25519 {
                Base64UrlUnpadded::decode_vec(&jwk.x)?
            } else {
                let mut decoded = Base64UrlUnpadded::decode_vec(&jwk.x)?;
                let Some(y) = &jwk.y else {
                    return Err(unexpected!("missing y"));
                };
                decoded.extend(&Base64UrlUnpadded::decode_vec(y)?);
                decoded
            };
            builder = builder.add_recipient(&recipient.key_id, PublicKey::from_slice(&decoded)?);
        }

        let jwe = builder.build()?;
        self.buffer = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)?;

        // use JWE to build EncryptedProperty
        let mut encryption = EncryptionProperty {
            algorithm: jwe.protected.enc.clone(),
            initialization_vector: jwe.iv.clone(),
            key_encryption: vec![],
        };

        let recipients = match &jwe.recipients {
            Recipients::One(recipient) => vec![recipient.clone()],
            Recipients::Many { recipients } => recipients.clone(),
        };

        for recipient in &recipients {
            let header = &recipient.header;
            let Some(key_id) = header.kid.clone() else {
                return Err(unexpected!("missing key id"));
            };
            let Some(key_input) = config.recipients.iter().find(|r| r.key_id == key_id) else {
                return Err(unexpected!("recipient not found"));
            };

            //     if recipient.derivation_scheme == DerivationScheme::ProtocolPath
            //         && self.descriptor.protocol.is_none()
            //     {
            //         return Err(unexpected!(
            //             "`protocol` must be specified to use `protocols` encryption scheme"
            //         ));
            //     }
            //     if key_input.derivation_scheme == DerivationScheme::Schemas
            //         && self.descriptor.schema.is_none()
            //     {
            //         return Err(unexpected!(
            //             "`schema` must be specified to use `schema` encryption scheme"
            //         ));
            //     }

            let mut encrypted = EncryptedKey {
                root_key_id: key_id,
                algorithm: header.alg.clone(),
                ephemeral_public_key: header.epk.clone(),
                initialization_vector: header.iv.clone(),
                message_authentication_code: header.tag.clone(),
                encrypted_key: recipient.encrypted_key.clone(),
                derivation_scheme: key_input.derivation_scheme.clone(),
                derived_public_key: None,
            };

            // attach the public key when derivation scheme is protocol-context,
            // so that the responder to this message is able to encrypt the
            // content encryption key using the same protocol-context derived
            // public key, without needing the knowledge of the corresponding
            // private key
            if key_input.derivation_scheme == DerivationScheme::ProtocolContext {
                encrypted.derived_public_key = Some(key_input.public_key.clone());
            }

            encryption.key_encryption.push(encrypted);
        }

        self.encryption = Some(encryption);
        Ok(self)
    }

    /// Encryption output parameters for use when the data stream has been
    /// encrypted.
    #[must_use]
    pub fn encryption(&self) -> Option<EncryptionProperty> {
        self.encryption.clone()
    }
}

/// Encryption settings.
#[derive(Clone, Debug, Default)]
pub struct Encryption {
    /// The algorithm to use to encrypt the message data.
    pub content_algorithm: ContentAlgorithm,

    /// The algorithm to use to encrypt (or derive) the content encryption key
    /// (CEK).
    pub key_algorithm: KeyAlgorithm,

    /// An array of inputs specifying how the CEK key is to be encrypted. Each
    /// entry in the array will result in a unique ciphertext for the CEK.
    pub recipients: Vec<Recipient>,
}

/// Encryption key settings.
#[derive(Clone, Debug, Default)]
pub struct Recipient {
    /// The identifier of the recipient's public key used to encrypt the
    /// content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key used to encrypt the CEK.
    pub public_key: PublicKeyJwk,

    /// The content encryption key (CEK) derivation scheme.
    pub derivation_scheme: DerivationScheme,
}
