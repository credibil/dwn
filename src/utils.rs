//! # Utility Functions
//!
//! Utility functions that currenly have no better home.
//!
//! Sub-modules are used to group related functionality.

pub mod uri {
    use http::uri::Uri;

    use crate::{Result, unexpected};

    pub fn clean(uri: &str) -> Result<String> {
        let stripped = uri.strip_suffix('/').unwrap_or(uri);
        let parsed = stripped.parse::<Uri>()?;

        let scheme = parsed.scheme().map_or_else(|| "http://".to_string(), |s| format!("{s}://"));
        let Some(authority) = parsed.authority() else {
            return Err(unexpected!("protocol URI {uri} must have an authority"));
        };
        let path = parsed.path().trim_end_matches('/');

        Ok(format!("{scheme}{authority}{path}"))
    }

    pub fn validate(uri: &str) -> Result<()> {
        uri.parse::<Uri>().map_or_else(|_| Err(unexpected!("invalid URL: {uri}")), |_| Ok(()))
    }
}

/// Compute CID from a data value or stream.
pub mod cid {
    use std::io::Read;

    use cid::Cid;
    use futures::executor::block_on;
    use multihash_codetable::MultihashDigest;
    use serde::Serialize;

    use crate::Result;
    use crate::provider::BlockStore;
    use crate::store::data;

    const RAW: u64 = 0x55;
    // const DAG_CBOR: u64 = 0x71;

    /// Compute a CID from provided payload, serialized to CBOR.
    ///
    /// # Errors
    ///
    /// Fails when the payload cannot be serialized to CBOR.
    pub fn from_value<T: Serialize>(payload: &T) -> Result<String> {
        let mut buf = Vec::new();
        ciborium::into_writer(payload, &mut buf)?;
        let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
        Ok(Cid::new_v1(RAW, hash).to_string())
    }

    /// Compute a CID for the provided data reader.
    ///
    /// # Errors
    /// LATER: Add errors
    pub fn from_reader(reader: impl Read) -> Result<(String, usize)> {
        // use the default storage algorithm to compute CID and size
        block_on(async { data::put("owner", "record_id", "data_cid", reader, &MockStore).await })
    }

    struct MockStore;
    impl BlockStore for MockStore {
        async fn put(&self, _: &str, _: &str, _: &str, _: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(&self, _: &str, _: &str, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
            unimplemented!("MockStore::get")
        }

        async fn delete(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            unimplemented!("MockStore::delete")
        }

        async fn purge(&self, _: &str, _: &str) -> anyhow::Result<()> {
            unimplemented!("MockStore::purge")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scheme() {
        let url = "example.com/";
        let cleaned = uri::clean(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }

    #[test]
    fn trailing_slash() {
        let url = "http://example.com/";
        let cleaned = uri::clean(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }
}
