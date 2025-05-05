//! # Store
//!
//! The `store` module provides utilities for storing and retrieving messages
//! and associated data.
//!
//! The two primary types exposed by this module are [`Storable`] and [`Query`].
//!
//! [`Storable`] wraps each message with a unifying type used to simplify storage
//! and retrieval as well as providing a vehicle for attaching addtional data
//! alongside the message (i.e. indexes).

use anyhow::{Result, anyhow};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::query::{Cursor, Query};
use crate::{BlockStore, Document, Storable, index, ipfs};

/// Store a message in the underlying store.
pub async fn put(
    owner: &str, partition: &str, entry: &impl Storable, store: &impl BlockStore,
) -> Result<()> {
    let document = entry.document();

    // store entry block
    let message_cid = document.cid()?;
    store.delete(owner, partition, &message_cid).await?;
    store.put(owner, partition, &message_cid, &ipfs::encode_block(&document)?).await?;

    // index entry
    index::insert(owner, partition, entry, store).await
}

/// Queries the underlying store for matches to the provided query.
pub async fn query<T>(
    owner: &str, partition: &str, query: &Query, store: &impl BlockStore,
) -> Result<(Vec<T>, Option<Cursor>)>
where
    T: Serialize + DeserializeOwned,
{
    let mut results = index::query(owner, partition, query, store).await?;

    // return cursor when paging is used
    let limit = query.pagination.as_ref().map_or(0, |p| p.limit.unwrap_or(0));
    let cursor = if limit > 0 && limit < results.len() {
        let sort_field = query.sort.to_string();

        // set cursor to the last item remaining after the spliced result.
        results.pop().map(|item| Cursor {
            message_cid: item.message_cid.clone(),
            value: item.fields[&sort_field].clone(),
        })
    } else {
        None
    };

    let mut entries = Vec::new();
    for item in results {
        let Some(bytes) = store.get(owner, partition, &item.message_cid).await? else {
            return Err(anyhow!("missing block for message cid"));
        };
        entries.push(ipfs::decode_block(&bytes)?);
    }

    Ok((entries, cursor))
}

/// Fetch a single message by CID from the underlying store, returning
/// `None` if no message was found.
pub async fn get<T>(
    owner: &str, partition: &str, message_cid: &str, store: &impl BlockStore,
) -> Result<Option<T>>
where
    T: Serialize + DeserializeOwned,
{
    let Some(bytes) = store.get(owner, partition, message_cid).await? else {
        return Ok(None);
    };
    Ok(Some(ipfs::decode_block(&bytes)?))
}

/// Delete message associated with the specified id.
pub async fn delete(
    owner: &str, partition: &str, message_cid: &str, store: &impl BlockStore,
) -> Result<()> {
    index::delete(owner, partition, message_cid, store).await?;
    store.delete(owner, partition, message_cid).await
}
