//! Data record handling.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::Result;

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

    /// Compute a CID for the provided data stream.
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

/// Data stream for serializing/deserializing web node data.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DataStream {
    /// The data to be read.
    pub buffer: Vec<u8>,
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
        cid::from_reader(self.clone())
    }
}

impl From<Vec<u8>> for DataStream {
    fn from(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }
}

impl From<&[u8]> for DataStream {
    fn from(data: &[u8]) -> Self {
        Self {
            buffer: data.to_vec(),
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
