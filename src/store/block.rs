//! # Block
//!
//! Block represents a unit of data uniquely identified by a content identifier
//! (CID).

// #![allow(dead_code)]
// #![allow(unused_variables)]

use anyhow::{Result, anyhow};
use ipld_core::codec::Codec; // Links
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;

use crate::utils::cid;

const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB

/// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
///
/// # Errors
/// LATER: Add errors
pub fn encode<T>(payload: &T) -> Result<Vec<u8>>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    // encode payload
    let data = DagCborCodec::encode_to_vec(payload)?;
    if data.len() > MAX_BLOCK_SIZE {
        return Err(anyhow!("block is too large"));
    }
    // let links = DagCborCodec::links(&data).unwrap().collect::<Vec<_>>();

    Ok(data)
}

/// Decodes a block.
///
/// # Errors
/// LATER: Add errors
pub fn decode<T>(data: &[u8]) -> Result<T>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    DagCborCodec::decode_from_slice(data).map_err(Into::into)
}

/// Block represents a unit of data uniquely identified by a content identifier
pub struct Block {
    data: Vec<u8>,
    cid: String,
}

impl Block {
    /// Creates a new block.
    #[must_use]
    pub const fn new(cid: String, data: Vec<u8>) -> Self {
        Self { data, cid }
    }

    /// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn encode<T>(payload: &T) -> Result<Self>
    where
        T: Serialize + for<'a> Deserialize<'a>,
    {
        // encode payload
        let data = DagCborCodec::encode_to_vec(payload)?;
        if data.len() > MAX_BLOCK_SIZE {
            return Err(anyhow!("block is too large"));
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

    /// Decodes a block.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn decode<T>(&self) -> Result<T>
    where
        T: Serialize + for<'a> Deserialize<'a>,
    {
        DagCborCodec::decode_from_slice(&self.data).map_err(Into::into)
    }
}
