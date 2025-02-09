//! # IPFS-like Utilities

use std::collections::BTreeMap;
use std::io::Read;
use std::str::FromStr;

use ::cid::Cid;
use ipld_core::codec::Codec; // Links
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;

use crate::BlockStore;
use crate::utils::cid;
use crate::{Result, unexpected};

/// The maximum size of a message.
// pub const MAX_ENCODED_SIZE: usize = 30000;
const CHUNK_SIZE: usize = 64;
const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB
const PARTITION: &str = "DATA";

#[allow(dead_code)]
pub async fn import(
    owner: &str, record_id: &str, data_cid: &str, reader: impl Read, store: &impl BlockStore,
) -> Result<(String, usize)> {
    let mut links = vec![];
    let mut byte_count = 0;
    let mut reader = reader;

    // read data stream in chunks, storing each chunk as an IPLD block
    loop {
        let mut buffer = [0u8; CHUNK_SIZE];
        if let Ok(bytes_read) = reader.read(&mut buffer[..]) {
            if bytes_read == 0 {
                break;
            }
            // encode buffer to IPLD block
            let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
            let block = Block::encode(&ipld)?;

            // insert into the blockstore
            let cid = block.cid();
            store
                .put(owner, PARTITION, cid, block.data())
                .await
                .map_err(|e| unexpected!("issue storing data: {e}"))?;

            // save link to block
            let cid = Cid::from_str(cid).map_err(|e| unexpected!("issue parsing CID: {e}"))?;
            links.push(Ipld::Link(cid));
            byte_count += bytes_read;
        }
    }

    // the root block links the data blocks — yields the `data_cid`
    let root = Block::encode(&Ipld::List(links))?;

    // use a 'partition' CID to ensure the root data block is stored
    // by the owner, record_id, and data_cid
    let root_cid = root_cid(record_id, data_cid)?;
    store.put(owner, PARTITION, &root_cid, root.data()).await?;

    Ok((root.cid().to_string(), byte_count))
}

fn root_cid(record_id: &str, data_cid: &str) -> Result<String> {
    let root = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    Ok(root.cid().to_string())
}

/// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
#[cfg(feature = "server")]
pub fn encode_block<T>(payload: &T) -> Result<Vec<u8>>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    // encode payload
    let data = DagCborCodec::encode_to_vec(payload)
        .map_err(|e| unexpected!("issue encoding block: {e}"))?;
    if data.len() > MAX_BLOCK_SIZE {
        return Err(unexpected!("block is too large"));
    }
    Ok(data)
}

/// Decodes a block.
#[cfg(feature = "server")]
pub fn decode_block<T>(data: &[u8]) -> Result<T>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    DagCborCodec::decode_from_slice(data).map_err(|e| unexpected!("issue decoding block: {e}"))
}

/// Block represents a unit of data uniquely identified by a content identifier
pub struct Block {
    data: Vec<u8>,
    cid: String,
}

impl Block {
    /// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
    pub fn encode<T>(payload: &T) -> Result<Self>
    where
        T: Serialize + for<'a> Deserialize<'a>,
    {
        // encode payload
        let data = DagCborCodec::encode_to_vec(payload)
            .map_err(|e| unexpected!("issue encoding block: {e}"))?;
        if data.len() > MAX_BLOCK_SIZE {
            return Err(unexpected!("block is too large"));
        }
        let cid = cid::from_value(payload)?;

        Ok(Self { data, cid })
    }

    /// Returns the cid.
    #[must_use]
    pub fn cid(&self) -> &str {
        self.cid.as_str()
    }

    /// Returns the payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}
