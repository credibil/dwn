//! # CID (Content Identifier)

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;

use crate::Result;

const RAW: u64 = 0x55;

/// Compute a CID from provided payload, serialized to CBOR.
///
/// # Errors
/// TODO: Add errors
pub(crate) fn compute<T: Serialize>(payload: &T) -> Result<String> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)?;
    let hash = Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(RAW, hash).to_string())
}
