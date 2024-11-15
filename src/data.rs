//! Data record handling.

use std::io::{self, Read, Write};
use std::str::FromStr;

use libipld::block::Block;
use libipld::cbor::DagCborCodec;
use libipld::cid::multihash::Code;
use libipld::ipld::Ipld;
use libipld::store::DefaultParams;
use serde::{Deserialize, Serialize};

use crate::provider::BlockStore;
use crate::{unexpected, Result};

const CHUNK_SIZE: usize = 16;

/// Compuet CID from a data value or stream.
pub mod cid {

    use cid::Cid;
    use multihash_codetable::MultihashDigest;
    use serde::Serialize;

    use crate::Result;

    const RAW: u64 = 0x55;

    /// Compute a CID from provided payload, serialized to CBOR.
    ///
    /// # Errors
    /// TODO: Add errors
    pub(crate) fn from_value<T: Serialize>(payload: &T) -> Result<String> {
        let mut buf = Vec::new();
        ciborium::into_writer(payload, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash).to_string())
    }
}

/// Data stream for serializing/deserializing web node data.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
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
    /// TODO: Add errors
    pub(crate) fn compute_cid(&mut self) -> Result<(String, usize)> {
        let mut links = vec![];
        let mut byte_count = 0;

        loop {
            let mut buffer = [0u8; CHUNK_SIZE];
            if let Ok(bytes_read) = self.read(&mut buffer[..]) {
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
    /// TODO: Add errors
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
    /// TODO: Add errors
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
        Self { buffer: data }
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
