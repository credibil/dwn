//! # Block
//!
//! Block represents a unit of data uniquely identified by a content identifier
//! (CID).

#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::{Result, anyhow};
use cid::Cid;
use ipld_core::codec::Codec; // Links
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;

const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB
const RAW: u64 = 0x55;
const DAG_CBOR: u64 = 0x71;


/// Encode a block using DAG-CBOR codec and SHA-2 256 hash.
pub fn encode<T>(payload: &T) -> Result<Block>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    // encode payload
    let data = DagCborCodec::encode_to_vec(payload)?;
    if data.len() > MAX_BLOCK_SIZE {
        return Err(anyhow!("block is too large"));
    }

    // let links = DagCborCodec::links(&data).unwrap().collect::<Vec<_>>();

    // compute CID
    let cid = compute_cid(payload)?;

    Ok(Block {
        cid,
        data,
        linked: None,
    })
}

/// Decodes a block.
pub fn decode<T>(data: &[u8]) -> Result<T>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    DagCborCodec::decode_from_slice(data).map_err(|e| e.into())
}

pub fn compute_cid<T>(payload: &T) -> Result<String>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)?;
    let hash = Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(DAG_CBOR, hash).to_string())
}

pub struct Block {
    data: Vec<u8>,
    cid: String,
    linked: Option<Vec<Block>>,
}

impl Block {
    pub fn new(cid: String, data: Vec<u8>) -> Self {
        Self {
            cid,
            data,
            linked: None,
        }
    }

    /// Returns the cid.
    pub fn cid(&self) -> &String {
        &self.cid
    }

    /// Returns the payload.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Decodes a block.
    pub fn decode<T>(&self) -> Result<T>
    where
        T: Serialize + for<'a> Deserialize<'a>,
    {
        DagCborCodec::decode_from_slice(&self.data).map_err(|e| e.into())
    }
}
