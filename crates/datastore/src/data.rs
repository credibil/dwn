//! Data record handling.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use anyhow::{Result, anyhow};
use ipld_core::ipld::Ipld;

use crate::BlockStore;
use crate::ipfs::{self, Block};

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 30000;

/// The maximum size of a block.
const PARTITION: &str = "DATA";

/// Put a data record into the block store.
pub async fn put(
    owner: &str, record_id: &str, data_cid: &str, reader: impl Read, store: &impl BlockStore,
) -> Result<(String, usize)> {
    ipfs::import(owner, record_id, data_cid, reader, store).await
}

/// Get a data record from the block store.
pub async fn get(
    owner: &str, record_id: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<Option<impl Read>> {
    // get the root block using the partition CID
    let root_cid = root_cid(record_id, data_cid)?;
    let Some(bytes) = store.get(owner, PARTITION, &root_cid).await? else {
        return Ok(None);
    };

    // the root blook contains a list of links to data blocks
    let Ipld::List(links) = ipfs::decode_block(&bytes)? else {
        return Ok(None);
    };

    // TODO: optimize by streaming the data blocks as fetched
    // fetch each data block
    let mut buf = Cursor::new(vec![]);

    for link in links {
        // get data block
        let Ipld::Link(link_cid) = link else {
            return Err(anyhow!("invalid link"));
        };
        let Some(bytes) = store.get(owner, PARTITION, &link_cid.to_string()).await? else {
            return Ok(None);
        };

        // get data block's payload
        let ipld_bytes = ipfs::decode_block(&bytes)?;
        let Ipld::Bytes(bytes) = ipld_bytes else {
            return Ok(None);
        };

        buf.write_all(&bytes)?;
    }

    buf.set_position(0);
    Ok(Some(buf))
}

pub async fn delete(
    owner: &str, record_id: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<()> {
    let root_cid = root_cid(record_id, data_cid)?;
    store.delete(owner, PARTITION, &root_cid).await
}

fn root_cid(record_id: &str, data_cid: &str) -> Result<String> {
    let root = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    Ok(root.cid().to_string())
}
