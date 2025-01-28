//! Data record handling.

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 30000;

/// The maximum size of a block.
pub const CHUNK_SIZE: usize = 16;

/// Compute CID from a data value or stream.
pub mod cid {
    use std::io::Read;
    use std::str::FromStr;

    use cid::Cid;
    use ipld_core::ipld::Ipld;
    use multihash_codetable::MultihashDigest;
    use serde::Serialize;

    use super::CHUNK_SIZE;
    use crate::store::block;
    use crate::{Result, unexpected};

    const RAW: u64 = 0x55;

    /// Compute a CID from provided payload, serialized to CBOR.
    ///
    /// # Errors
    /// LATER: Add errors
    ///
    /// # Panics
    ///
    /// When the payload cannot be serialized.
    pub fn from_value<T: Serialize>(payload: &T) -> Result<String> {
        let mut buf = Vec::new();
        ciborium::into_writer(payload, &mut buf).expect("should serialize");
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash).to_string())
    }

    /// Compute a CID for the provided data reader.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn from_reader(reader: impl Read) -> Result<(String, usize)> {
        let mut links = vec![];
        let mut byte_count = 0;
        let mut reader = reader;

        loop {
            let mut buffer = [0u8; CHUNK_SIZE];
            if let Ok(bytes_read) = reader.read(&mut buffer[..]) {
                if bytes_read == 0 {
                    break;
                }

                // encode buffer to IPLD block
                let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
                let block = block::Block::encode(&ipld)?;

                // save block's CID as a link
                let cid = Cid::from_str(block.cid())
                    .map_err(|e| unexpected!("issue parsing CID: {e}"))?;
                links.push(Ipld::Link(cid));
                byte_count += bytes_read;
            }
        }

        let block = block::Block::encode(&Ipld::List(links))?;
        Ok((block.cid().to_string(), byte_count))
    }
}
