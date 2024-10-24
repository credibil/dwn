//! # CID (Content Identifier)

use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;

const RAW: u64 = 0x55;

/// Compute a CID from provided payload.
///
/// # Errors
/// TODO: Add errors
pub(crate) fn compute<T: Serialize>(payload: &T) -> anyhow::Result<String> {
    // serialize to CBOR
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)?;

    let hash = Code::Sha2_256.digest(&buf);
    let cid = cid::Cid::new_v1(RAW, hash);

    Ok(cid.to_string())
}

// /// Computes V1 CID of the DAG comprised by chunking data into unixfs DAG-PB
// /// encoded blocks
// pub(crate) async fn compute_from_bytes(data: &[u8]) -> Result<String> {
// TODO: Implement IPFS importer

// import { importer } from 'ipfs-unixfs-importer';
// const asyncBlocks = importer([{ content }], new BlockstoreMock(), { cidVersion: 1 });

// // NOTE: the last block contains the root CID
// let block;
// for await (block of asyncBlocks) { ; }

// return block ? block.cid.toString() : '';

//     todo!()
// }
