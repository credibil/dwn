//! # Event Log

use super::Pagination;
use crate::event::Event;
use crate::provider::BlockStore;
use crate::store::{Cursor, Entry, Query, Sort, block, index};
use crate::{Result, unexpected};

/// Adds a message event to a owner's event log.
pub async fn append(owner: &str, event: &Event, store: &impl BlockStore) -> Result<()> {
    // store entry block
    let message_cid = event.cid()?;
    store.delete(owner, &message_cid).await?;
    store.put(owner, &message_cid, &block::encode(event)?).await?;

    // add a 'watermark' index entry for sorting and pagination
    let mut event = event.clone();
    let watermark = ulid::Ulid::new().to_string();
    event.indexes.insert("watermark".to_string(), watermark);

    index::insert(owner, &event, store).await
}

#[allow(clippy::unused_async)]
pub async fn events(
    owner: &str, cursor: Option<Cursor>, store: &impl BlockStore,
) -> Result<(Vec<Entry>, Option<Cursor>)> {
    let q = Query {
        match_sets: vec![],
        pagination: Some(Pagination {
            limit: Some(100),
            cursor,
        }),
        sort: Sort::TimestampAsc,
    };

    query(owner, &q, store).await
}

/// Retrieves a filtered set of events that occurred after a the cursor
/// provided, accepts multiple filters. If no cursor is provided, all
/// events for a given owner and filter combo will be returned. The cursor
/// is a `message_cid`.
///
/// Returns an array of `message_cid`s that represent the events.
pub async fn query(
    owner: &str, query: &Query, store: &impl BlockStore,
) -> Result<(Vec<Entry>, Option<Cursor>)> {
    let mut results = index::query(owner, query, store).await?;

    // return cursor when paging is used
    let limit = query.pagination.as_ref().map_or(0, |p| p.limit.unwrap_or(0));
    let cursor = if limit > 0 && limit < results.len() {
        // set cursor to the last item remaining after the spliced result.
        results.pop().map(|item| Cursor {
            message_cid: item.message_cid.clone(),
            value: item.fields["watermark"].clone(),
        })
    } else {
        None
    };

    let mut entries = Vec::new();
    for item in results {
        let Some(bytes) = store.get(owner, &item.message_cid).await? else {
            return Err(unexpected!("missing block for message cid"));
        };
        entries.push(block::decode(&bytes)?);
    }

    Ok((entries, cursor))
}

/// Deletes event for the specified `message_cid`.
pub async fn delete(owner: &str, message_cid: &str, store: &impl BlockStore) -> Result<()> {
    index::delete(owner, message_cid, store).await?;
    store.delete(owner, message_cid).await.map_err(Into::into)
}
