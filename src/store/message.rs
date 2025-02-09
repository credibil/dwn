//! # Message Store

use crate::interfaces::{Cursor, Document};
use crate::provider::BlockStore;
use crate::store::{Query, Storable, block, index};
use crate::{Result, unexpected};

const PARTITION: &str = "MESSAGE";

/// Store a message in the underlying store.
pub async fn put(owner: &str, entry: &impl Storable, store: &impl BlockStore) -> Result<()> {
    let document = entry.document();

    // store entry block
    let message_cid = document.cid()?;
    store.delete(owner, PARTITION, &message_cid).await?;
    store.put(owner, PARTITION, &message_cid, &block::encode(&document)?).await?;

    // index entry
    index::insert(owner, PARTITION, entry, store).await
}

/// Queries the underlying store for matches to the provided query.
pub async fn query(
    owner: &str, query: &Query, store: &impl BlockStore,
) -> Result<(Vec<Document>, Option<Cursor>)> {
    let mut results = index::query(owner, PARTITION, query, store).await?;

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
        let Some(bytes) = store.get(owner, PARTITION, &item.message_cid).await? else {
            return Err(unexpected!("missing block for message cid"));
        };
        entries.push(block::decode(&bytes)?);
    }

    Ok((entries, cursor))
}

/// Fetch a single message by CID from the underlying store, returning
/// `None` if no message was found.
pub async fn get(
    owner: &str, message_cid: &str, store: &impl BlockStore,
) -> Result<Option<Document>> {
    let Some(bytes) = store.get(owner, PARTITION, message_cid).await? else {
        return Ok(None);
    };
    Ok(Some(block::decode(&bytes)?))
}

/// Delete message associated with the specified id.
pub async fn delete(owner: &str, message_cid: &str, store: &impl BlockStore) -> Result<()> {
    index::delete(owner, PARTITION, message_cid, store).await?;
    store.delete(owner, PARTITION, message_cid).await.map_err(Into::into)
}
