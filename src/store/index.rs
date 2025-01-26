//! # Index Store
//!
//! The index store is responsible for storing and retrieving message indexes.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound::{self, Excluded, Included, Unbounded};

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use super::RecordsFilter;
use crate::provider::BlockStore;
use crate::store::{
    Entry, EventsQuery, GrantedQuery, ProtocolsQuery, Query, RecordsQuery, TagFilter, block,
};
use crate::{Interface, Method, Result, unexpected};

// const NULL: u8 = 0x00;
// const MAX: u8 = 0x7E;
const NULL: char = '\u{100000}';
const MAX: char = '\u{10ffff}';

/// Insert an entry's queryable fields into indexes.
///
/// # Errors
/// LATER: Add errors
pub async fn insert(owner: &str, entry: &Entry, store: &impl BlockStore) -> Result<()> {
    let message_cid = entry.cid()?;

    let fields = &entry.indexes;
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    // remove the previous index entries for message
    delete(owner, &message_cid, store).await?;

    for (field, value) in &entry.indexes {
        let mut index = indexes.get(field).await?;
        index.insert(value, IndexItem {
            fields: entry.indexes.clone(),
            message_cid: message_cid.clone(),
        });
        indexes.put(index).await?;
    }

    // add reverse lookup to use when message is updated or deleted
    let mut index = indexes.get("message_cid").await?;
    index.items.insert(message_cid.clone(), IndexItem {
        fields: entry.indexes.clone(),
        message_cid,
    });
    indexes.put(index).await?;

    Ok(())
}

/// Query an index for matching entries.
///
/// # Errors
/// LATER: Add errors
pub async fn query(owner: &str, query: &Query, store: &impl BlockStore) -> Result<Vec<IndexItem>> {
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    match query {
        Query::Records(rq) => {
            // choose query strategy
            for filter in &rq.filters {
                if !filter.is_concise() {
                    return indexes.query_full(rq).await;
                }
            }
            indexes.query_concise(rq).await
        }
        Query::Protocols(pq) => indexes.query_protocols(pq).await,
        Query::Granted(gq) => indexes.query_granted(gq).await,
        Query::Messages(mq) => indexes.query_events(mq).await,
    }
}

/// Delete entry specified by `message_cid` from indexes.
///
/// # Errors
/// LATER: Add errors
pub async fn delete(owner: &str, message_cid: &str, store: &impl BlockStore) -> Result<()> {
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    // if this is an update, remove the previous message indexes
    let messages = indexes.get("message_cid").await?;
    if let Some(item) = messages.items.get(message_cid) {
        for (field, value) in &item.fields {
            let mut index = indexes.get(field).await?;
            let x = index.remove(value, message_cid);
            indexes.put(index).await?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct Cid(String);

/// Indexes store.
///
/// # Errors
/// LATER: Add errors
pub struct Indexes<'a, S: BlockStore> {
    owner: &'a str,
    store: &'a S,
}

impl<S: BlockStore> Indexes<'_, S> {
    /// Get an index.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn get(&self, field: &str) -> Result<Index> {
        let index_cid = block::compute_cid(&Cid(format!("{}-{}", self.owner, field)))?;

        // get the index block or return empty index
        let Some(data) = self.store.get(self.owner, &index_cid).await? else {
            return Ok(Index::new(field));
        };
        block::decode(&data).map_err(Into::into)
    }

    /// Update an index.
    ///
    /// # Errors
    /// LATER: Add errors
    pub async fn put(&self, index: Index) -> Result<()> {
        let index_cid = block::compute_cid(&Cid(format!("{}-{}", self.owner, index.field)))?;

        // update the index block
        self.store.delete(self.owner, &index_cid).await?;
        self.store.put(self.owner, &index_cid, &block::encode(&index)?).await.map_err(Into::into)
    }

    // This query strategy is used when the filter contains a property that
    // leads to a concise, or small, set of results that can be sorted and
    // paged in memory.
    //
    // This strategy is employed when the filter contains one of `record_id`,
    // `context_id`, `protocol_path`, `parent_id`, or `schema`.
    async fn query_concise(&self, query: &RecordsQuery) -> Result<Vec<IndexItem>> {
        let mut matches = HashSet::new();
        let mut results = BTreeMap::new();

        let sort_field = query.sort.to_string();

        for filter in &query.filters {
            // choose the best index to use for the filter
            let Some((field, value)) = filter.as_concise() else {
                continue;
            };
            let index = self.get(&field).await?;

            // 1. use the index to find candidate matches
            // 2. compare each entry against the current filter
            for item in index.matches(value) {
                // short circuit when previously matched
                if matches.contains(&item.message_cid) {
                    continue;
                }
                let archived = item.fields.get("archived");
                if !query.include_archived && archived.unwrap_or(&String::new()) == "true" {
                    continue;
                }
                if item.fields.get("interface") != Some(&Interface::Records.to_string()) {
                    continue;
                }
                if let Some(method) = &query.method {
                    if item.fields.get("method") != Some(&method.to_string()) {
                        continue;
                    }
                }

                if item.is_match(filter)? {
                    matches.insert(item.message_cid.clone());

                    // sort results as we collect using `message_cid` as a tie-breaker
                    let sort_key = format!("{}{}", &item.fields[&sort_field], item.message_cid);
                    results.insert(sort_key, item.clone());
                }
            }
        }

        // collect results in sorted order
        let mut items = if query.sort.is_ascending() {
            results.values().cloned().collect::<Vec<IndexItem>>()
        } else {
            results.values().rev().cloned().collect::<Vec<IndexItem>>()
        };

        // paginate results
        if let Some(pagination) = &query.pagination {
            let limit = pagination.limit.unwrap_or(items.len());
            let start = pagination.cursor.as_ref().map_or(0, |cursor| {
                items.iter().position(|item| item.message_cid == cursor.message_cid).unwrap_or(0)
            });

            let mut end = start + limit + 1;
            if end > items.len() {
                end = items.len();
            }
            items = items[start..end].to_vec();
        }

        Ok(items)
    }

    // This query strategy is used when the filter will return a larger set of
    // results.
    async fn query_full(&self, query: &RecordsQuery) -> Result<Vec<IndexItem>> {
        let mut items = Vec::new();
        let (limit, cursor) =
            query.pagination.as_ref().map_or((None, None), |p| (p.limit, p.cursor.as_ref()));

        // the location in the index to begin querying from
        let start_key =
            cursor.map_or(Unbounded, |c| Included(format!("{}{NULL}{}", c.value, c.message_cid)));
        let index = self.get(&query.sort.to_string()).await?;

        // starting from `start_key`, select matching index items until limit
        for (value, item) in index.lower_bound(start_key) {
            if item.fields.get("archived") == Some(&"true".to_string()) && !query.include_archived {
                continue;
            }
            if item.fields.get("interface") != Some(&Interface::Records.to_string()) {
                continue;
            }
            if let Some(method) = &query.method {
                if item.fields.get("method") != Some(&method.to_string()) {
                    continue;
                }
            }

            // match entry against any filter
            for filter in &query.filters {
                if item.is_match(filter)? {
                    items.push(item.clone());
                    break;
                }
            }

            // stop when page limit + 1 is reached
            if let Some(lim) = limit {
                if items.len() == lim + 1 {
                    break;
                }
            }
        }

        Ok(items)
    }

    async fn query_granted(&self, query: &GrantedQuery) -> Result<Vec<IndexItem>> {
        let mut results = Vec::new();

        let index = self.get("protocol").await?;
        for item in index.items.values() {
            if item.fields.get("interface") != Some(&Interface::Records.to_string()) {
                continue;
            }
            if item.fields.get("method") != Some(&Method::Write.to_string()) {
                continue;
            }

            if Some(&query.permission_grant_id) != item.fields.get("permissionGrantId") {
                continue;
            }

            let default = String::new();
            let date_str = item.fields.get("dateCreated").unwrap_or(&default);
            let created = DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| unexpected!("issue parsing date: {e}"))?;
            if !query.date_created.contains(&created.into()) {
                continue;
            }

            // sort results as we collect using `message_cid` as a tie-breaker
            let sort_key = format!("{}{}", &item.fields["messageTimestamp"], item.message_cid);
            results.push(item.clone());
        }

        Ok(results)
    }

    async fn query_protocols(&self, query: &ProtocolsQuery) -> Result<Vec<IndexItem>> {
        let mut results = BTreeMap::new();

        let index = self.get("protocol").await?;
        for item in index.items.values() {
            if item.fields.get("interface") != Some(&Interface::Protocols.to_string()) {
                continue;
            }
            if let Some(protocol) = &query.protocol {
                if item.fields.get("protocol") != Some(protocol) {
                    continue;
                }
            }
            if let Some(published) = &query.published {
                let default = String::from("false");
                if &published.to_string() != item.fields.get("published").unwrap_or(&default) {
                    continue;
                }
            }

            // sort results as we collect using `message_cid` as a tie-breaker
            let sort_key = format!("{}{}", &item.fields["messageTimestamp"], item.message_cid);
            results.insert(sort_key, item.clone());
        }

        Ok(results.values().cloned().collect())
    }

    // This query strategy is used when the filter will return a larger set of
    // results.
    async fn query_events(&self, query: &EventsQuery) -> Result<Vec<IndexItem>> {
        let mut items = Vec::new();
        let mut matches = HashSet::new();

        let (limit, cursor) =
            query.pagination.as_ref().map_or((None, None), |p| (p.limit, p.cursor.as_ref()));

        // the location in the index to begin querying from
        let start_key =
            cursor.map_or(Unbounded, |c| Included(format!("{}{NULL}{}", c.value, c.message_cid)));
        let index = self.get("messageTimestamp").await?;

        // starting from `start_key`, select matching index items until limit
        for (value, item) in index.lower_bound(Unbounded) {
            if matches.contains(&item.message_cid) {
                continue;
            }

            if query.match_sets.is_empty() {
                matches.insert(item.message_cid.clone());
                items.push(item.clone());
                continue;
            }

            for match_set in &query.match_sets {
                for matcher in match_set {
                    let Some(field_val) = item.fields.get(&matcher.field) else {
                        continue;
                    };
                    if !matcher.is_match(field_val)? {
                        continue;
                    }
                    matches.insert(item.message_cid.clone());
                    items.push(item.clone());
                }
            }

            // stop when page limit + 1 is reached
            if let Some(lim) = limit {
                if items.len() == lim + 1 {
                    break;
                }
            }
        }

        Ok(items)
    }
}

/// `Index` wraps a physical index, providing helper methods.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    field: String,
    items: BTreeMap<String, IndexItem>,
}

/// Represents an index entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexItem {
    /// The CID pointing to the indexed message.
    pub message_cid: String,

    /// The fields indexed for the message.
    pub fields: HashMap<String, String>,
}

impl Index {
    fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            items: BTreeMap::new(),
        }
    }

    fn insert(&mut self, value: &str, item: IndexItem) {
        let key = format!("{value}{NULL}{}", item.message_cid);
        self.items.insert(key, item);
    }

    fn remove(&mut self, value: &str, message_cid: &str) -> Option<IndexItem> {
        let key = format!("{value}{NULL}{message_cid}");
        self.items.remove(&key)
    }

    fn lower_bound(&self, lower: Bound<String>) -> Range<String, IndexItem> {
        self.items.range((lower, Unbounded))
    }

    fn matches(&self, value: String) -> Vec<&IndexItem> {
        let index = &self.items;
        let upper = format!("{value}{MAX}");
        index.range((Excluded(value), Excluded(upper))).map(|(_, item)| item).collect()
    }
}

impl IndexItem {
    /// Check if the index item matches the filter.
    ///
    /// # Errors
    /// LATER: Add errors
    #[allow(clippy::too_many_lines)]
    pub fn is_match(&self, filter: &RecordsFilter) -> Result<bool> {
        let empty = &String::new();
        let fields = &self.fields;

        if let Some(author) = &filter.author {
            if !author.to_vec().contains(fields.get("author").unwrap_or(empty)) {
                return Ok(false);
            }
        }
        if let Some(attester) = filter.attester.clone() {
            if Some(&attester) != fields.get("attester") {
                return Ok(false);
            }
        }
        if let Some(recipient) = &filter.recipient {
            if !recipient.to_vec().contains(fields.get("recipient").unwrap_or(empty)) {
                return Ok(false);
            }
        }
        if let Some(protocol) = &filter.protocol {
            if Some(protocol) != fields.get("protocol") {
                return Ok(false);
            }
        }
        if let Some(protocol_path) = &filter.protocol_path {
            if Some(protocol_path) != fields.get("protocolPath") {
                return Ok(false);
            }
        }
        if let Some(published) = &filter.published {
            if Some(&published.to_string()) != fields.get("published") {
                return Ok(false);
            }
        }
        if let Some(context_id) = &filter.context_id {
            if !fields.get("contextId").unwrap_or(empty).starts_with(context_id) {
                return Ok(false);
            }
        }
        if let Some(schema) = &filter.schema {
            if Some(schema) != fields.get("schema") {
                return Ok(false);
            }
        }
        if let Some(record_id) = &filter.record_id {
            if Some(record_id) != fields.get("record_id") {
                return Ok(false);
            }
        }
        if let Some(parent_id) = &filter.parent_id {
            if Some(parent_id) != fields.get("parentId") {
                return Ok(false);
            }
        }
        if let Some(tags) = &filter.tags {
            for (property, tag_filter) in tags {
                let tag_value = fields.get(&format!("tag.{property}")).unwrap_or(empty);
                match tag_filter {
                    TagFilter::StartsWith(value) => {
                        if !tag_value.starts_with(value) {
                            return Ok(false);
                        }
                    }
                    TagFilter::Range(range) => {
                        let tag_int = tag_value
                            .parse::<usize>()
                            .map_err(|e| unexpected!("issue parsing tag: {e}"))?;
                        if !range.contains(&tag_int) {
                            return Ok(false);
                        }
                    }
                    TagFilter::Equal(value) => {
                        if Some(tag_value.as_str()) != value.as_str() {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        if let Some(data_format) = &filter.data_format {
            if Some(data_format) != fields.get("dataFormat") {
                return Ok(false);
            }
        }
        if let Some(data_size) = &filter.data_size {
            let size_str = fields.get("dataSize").unwrap_or(empty);
            let size: usize =
                size_str.parse::<usize>().map_err(|e| unexpected!("issue parsing size: {e}"))?;

            if !data_size.contains(&size) {
                return Ok(false);
            }
        }
        if let Some(data_cid) = &filter.data_cid {
            if Some(data_cid) != fields.get("dataCid") {
                return Ok(false);
            }
        }
        if let Some(date_created) = &filter.date_created {
            let date_str = fields.get("dateCreated").unwrap_or(empty);
            let created = DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| unexpected!("issue parsing date: {e}"))?;
            if !date_created.contains(&created.into()) {
                return Ok(false);
            }
        }
        if let Some(date_published) = &filter.date_published {
            let date_str = fields.get("datePublished").unwrap_or(empty);
            let published = DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| unexpected!("issue parsing date: {e}"))?;
            if !date_published.contains(&published.into()) {
                return Ok(false);
            }
        }
        if let Some(date_updated) = &filter.date_updated {
            let date_str = fields.get("messageTimestamp").unwrap_or(empty);
            let timestamp = DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| unexpected!("issue parsing date: {e}"))?;
            if !date_updated.contains(&timestamp.into()) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

struct IndexesBuilder<O, S> {
    owner: O,
    indexes: Option<BTreeMap<String, String>>,
    store: S,
}

/// Store not set on IndexesBuilder.
#[doc(hidden)]
struct NoOwner;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
struct Owner<'a>(&'a str);

/// Store not set on IndexesBuilder.
#[doc(hidden)]
struct NoStore;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
struct Store<'a, S: BlockStore>(&'a S);

impl IndexesBuilder<NoOwner, NoStore> {
    const fn new() -> Self {
        Self {
            owner: NoOwner,
            indexes: None,
            store: NoStore,
        }
    }
}

impl<S> IndexesBuilder<NoOwner, S> {
    fn owner(self, owner: &str) -> IndexesBuilder<Owner, S> {
        IndexesBuilder {
            owner: Owner(owner),
            indexes: None,
            store: self.store,
        }
    }
}

impl<O> IndexesBuilder<O, NoStore> {
    fn store<S: BlockStore>(self, store: &S) -> IndexesBuilder<O, Store<'_, S>> {
        IndexesBuilder {
            owner: self.owner,
            indexes: self.indexes,
            store: Store(store),
        }
    }
}

impl<'a, S: BlockStore> IndexesBuilder<Owner<'a>, Store<'a, S>> {
    fn build(self) -> Indexes<'a, S> {
        Indexes {
            owner: self.owner.0,
            store: self.store.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;
    use blockstore::{Blockstore as _, InMemoryBlockstore};
    use rand::RngCore;
    use test_node::key_store::{self, ALICE_DID};

    use super::*;
    use crate::clients::protocols::{ConfigureBuilder, Definition};
    use crate::clients::records::{Data, WriteBuilder};
    use crate::data::DataStream;
    use crate::store::{RecordsFilter, RecordsQuery};
    // use crate::data::MAX_ENCODED_SIZE;
    // use crate::store::block;

    #[tokio::test]
    async fn query_records() {
        let block_store = BlockStoreImpl::new();
        let alice_signer = key_store::signer(ALICE_DID);

        let mut data = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut data);
        let stream = DataStream::from(data.to_vec());

        let write = WriteBuilder::new()
            .data(Data::Stream(stream.clone()))
            .published(true)
            .sign(&alice_signer)
            .build()
            .await
            .unwrap();
        let entry = Entry::from(&write);

        // add message
        let message_cid = entry.cid().unwrap();
        let block = block::encode(&entry).unwrap();
        block_store.put(ALICE_DID, &message_cid, &block).await.unwrap();

        // update indexes
        super::insert(ALICE_DID, &entry, &block_store).await.unwrap();

        // execute query
        let query = Query::Records(RecordsQuery {
            filters: vec![
                RecordsFilter::new()
                    // .add_author(ALICE_DID)
                    // .data_size(Range::new().gt(8)),
                    .record_id(write.record_id),
            ],
            ..Default::default()
        });
        let items = super::query(ALICE_DID, &query, &block_store).await.unwrap();
    }

    #[tokio::test]
    async fn query_protocols() {
        let block_store = BlockStoreImpl::new();
        let alice_signer = key_store::signer(ALICE_DID);

        let configure = ConfigureBuilder::new()
            .definition(Definition::new("http://minimal.xyz"))
            .build(&alice_signer)
            .await
            .expect("should build");

        let entry = Entry::from(&configure);

        // add message
        let message_cid = entry.cid().unwrap();
        let block = block::encode(&entry).unwrap();
        block_store.put(ALICE_DID, &message_cid, &block).await.unwrap();

        // update indexes
        super::insert(ALICE_DID, &entry, &block_store).await.unwrap();

        // execute query
        let query = Query::Protocols(ProtocolsQuery {
            protocol: Some("http://minimal.xyz".to_string()),
            ..Default::default()
        });
        let items = super::query(ALICE_DID, &query, &block_store).await.unwrap();
    }

    // #[test]
    // fn test_range() {
    //     let mut entries = vec!["a", "b", "c", "d", "e"];

    //     assert_eq!(entries[0..10], entries);
    //     // assert_eq!(range[0].len(), 2);
    // }

    struct BlockStoreImpl {
        blockstore: InMemoryBlockstore<64>,
    }

    impl BlockStoreImpl {
        pub fn new() -> Self {
            Self {
                blockstore: InMemoryBlockstore::<64>::new(),
            }
        }
    }

    impl BlockStore for BlockStoreImpl {
        async fn put(&self, owner: &str, cid: &str, data: &[u8]) -> Result<()> {
            // HACK: convert libipld CID to blockstore CID
            let block_cid = cid::Cid::from_str(cid)?;
            self.blockstore.put_keyed(&block_cid, data).await.map_err(Into::into)
        }

        async fn get(&self, owner: &str, cid: &str) -> Result<Option<Vec<u8>>> {
            // HACK: convert libipld CID to blockstore CID
            let block_cid = cid::Cid::try_from(cid)?;
            let Some(bytes) = self.blockstore.get(&block_cid).await? else {
                return Ok(None);
            };
            Ok(Some(bytes))
        }

        async fn delete(&self, owner: &str, cid: &str) -> Result<()> {
            let cid = cid::Cid::from_str(cid)?;
            self.blockstore.remove(&cid).await?;
            Ok(())
        }

        async fn purge(&self) -> Result<()> {
            unimplemented!()
        }
    }
}
