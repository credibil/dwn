//! # IPFS-like Utilities

use std::io::Read;

use ipld_core::codec::Codec; // Links
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;

use crate::provider::BlockStore;
use crate::utils::cid;
use crate::{Result, unexpected};

/// The maximum size of a message.
// pub const MAX_ENCODED_SIZE: usize = 30000;
const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB

#[allow(dead_code)]
pub fn import(_reader: impl Read, _store: &impl BlockStore) -> Result<String> {
    // importer([{ content }], new BlockstoreMock(), { cidVersion: 1 });
    todo!()
}

/// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
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
