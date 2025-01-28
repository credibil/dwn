//! # Utils
//!
//! TODO: documentation

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
    use std::str::FromStr;

    use cid::Cid;
    use ipld_core::ipld::Ipld;
    use multihash_codetable::MultihashDigest;
    use serde::Serialize;

    use crate::store::block;
    use crate::store::data::CHUNK_SIZE;
    use crate::{Result, unexpected};

    const RAW: u64 = 0x55;
    // const DAG_CBOR: u64 = 0x71;

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
