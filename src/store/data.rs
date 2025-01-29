//! Data record handling.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::str::FromStr;

use cid::Cid;
use ipld_core::ipld::Ipld;

use crate::provider::BlockStore;
use crate::store::block::{self, Block};
use crate::{Result, unexpected};

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 30000;

/// The maximum size of a block.
pub(crate) const CHUNK_SIZE: usize = 1024; // 1 KiB

/// Put a data record into the block store.
pub(crate) async fn put(
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
                .put(owner, cid, block.data())
                .await
                .map_err(|e| unexpected!("issue storing data: {e}"))?;

            // save link to block
            let cid = Cid::from_str(cid).map_err(|e| unexpected!("issue parsing CID: {e}"))?;
            links.push(Ipld::Link(cid));
            byte_count += bytes_read;
        }
    }

    // create a root block linking to the data blocks
    // this is the block that yields the `data_cid`
    let root = Block::encode(&Ipld::List(links))?;
    store.put(owner, root.cid(), root.data()).await?;

    // the 'partition' as a block helps isolate the data by owner and record_id
    // println!("put: owner: {owner}, record_id: {record_id}, data_cid: {data_cid}");
    let partition = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("owner"), Ipld::String(owner.to_string())),
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;
    store.put(owner, partition.cid(), partition.data()).await?;

    Ok((root.cid().to_string(), byte_count))
}

/// Get a data record from the block store.
pub(crate) async fn get(
    owner: &str, record_id: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<Option<impl Read>> {
    // get the partition block
    // println!("get: owner: {owner}, record_id: {record_id}, data_cid: {data_cid}");
    let partition = Block::encode(&Ipld::Map(BTreeMap::from([
        (String::from("owner"), Ipld::String(owner.to_string())),
        (String::from("record_id"), Ipld::String(record_id.to_string())),
        (String::from("data_cid"), Ipld::String(data_cid.to_string())),
    ])))?;

    // get partition block
    let Some(_) = store.get(owner, partition.cid()).await? else {
        return Ok(None);
        //return Err(unexpected!("`owner`, `record_id`, and `data_cid` do not match"));
    };

    // get root block
    let Some(bytes) = store.get(owner, data_cid).await? else {
        return Ok(None);
    };

    // the root blook contains a list of links to data blocks
    let Ipld::List(links) = block::decode(&bytes)? else {
        return Ok(None);
    };

    // TODO: optimize by streaming the data blocks as fetched
    // fetch each data block
    let mut buf = Cursor::new(vec![]);

    for link in links {
        // get data block
        let Ipld::Link(link_cid) = link else {
            return Err(unexpected!("invalid link"));
        };
        let Some(bytes) = store.get(owner, &link_cid.to_string()).await? else {
            return Ok(None);
        };

        // get data block's payload
        let ipld_bytes = block::decode(&bytes)?;
        let Ipld::Bytes(bytes) = ipld_bytes else {
            return Ok(None);
        };

        buf.write_all(&bytes)?;
    }

    buf.set_position(0);
    Ok(Some(buf))
}

pub(crate) async fn delete(
    owner: &str, _record_id: &str, data_cid: &str, store: &impl BlockStore,
) -> Result<()> {
    Ok(store.delete(owner, data_cid).await?)
}
