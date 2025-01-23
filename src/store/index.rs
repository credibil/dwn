//! # Index Store
//!
//! The index store is responsible for storing and retrieving message indexes.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound::{self, Excluded, Included, Unbounded};

use serde::{Deserialize, Serialize};

use crate::provider::BlockStore;
use crate::store::{Entry, ProtocolsQuery, Query, RecordsQuery, block};
use crate::{Result, unexpected};

const NULL: u8 = 0x00;
const MAX: u8 = 0x7E;

pub async fn insert(owner: &str, entry: &Entry, store: &impl BlockStore) -> Result<()> {
    let message_cid = entry.cid()?;

    let fields = &entry.indexes;
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    for (field, value) in &entry.indexes {
        let mut index = indexes.get(field).await?;

        let item = IndexItem {
            fields: fields.clone(),
            message_cid: message_cid.clone(),
        };
        index.insert(value, item);
        indexes.update(index).await?;
    }

    // TODO: add reverse lookup for deletes: {"message_cid": fields[]}
    // index.insert(message_cid, fields);

    Ok(())
}

pub async fn query(owner: &str, query: &Query, store: &impl BlockStore) -> Result<Vec<Entry>> {
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    if let Query::Records(rq) = query {
        let mut concise = true;
        for filter in &rq.filters {
            if !filter.is_concise() {
                concise = false;
                break;
            }
        }

        // choose strategy for query
        if concise {
            return indexes.query_concise(rq).await;
        }
        return indexes.query_full(rq).await;
    };

    if let Query::Protocols(pq) = query {
        return indexes.query_protocols(pq).await;
    }

    Err(unexpected!("unsupported query type"))
}

#[derive(Serialize)]
struct Cid(String);

pub struct Indexes<'a, S: BlockStore> {
    owner: &'a str,
    store: &'a S,
}

impl<S: BlockStore> Indexes<'_, S> {
    /// Get an index.
    pub async fn get(&self, field: &str) -> Result<Index> {
        let index_cid = block::compute_cid(&Cid(format!("{}-{}", self.owner, field)))?;

        // get the index block or return empty index
        let Some(data) = self.store.get(self.owner, &index_cid).await? else {
            return Ok(Index::new(field));
        };
        block::decode(&data).map_err(Into::into)
    }

    /// Update an index.
    pub async fn update(&self, index: Index) -> Result<()> {
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
    async fn query_concise(&self, query: &RecordsQuery) -> Result<Vec<Entry>> {
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

                // use full entry to  match against other filter properties
                let Some(bytes) = self.store.get(self.owner, &item.message_cid).await? else {
                    return Err(unexpected!("entry not found"));
                };
                let entry = block::decode(&bytes)?;
                if filter.is_match(&entry) {
                    matches.insert(item.message_cid.clone());

                    // sort results as we collect using `message_cid` as a tie-breaker
                    let sort_key = format!("{}{}", &item.fields[&sort_field], item.message_cid);
                    results.insert(sort_key, entry);
                }
            }
        }

        // collect results in sorted order
        let mut entries = if query.sort.is_ascending() {
            results.values().cloned().collect::<Vec<Entry>>()
        } else {
            results.values().rev().cloned().collect::<Vec<Entry>>()
        };

        // paginate results
        if let Some(pagination) = &query.pagination {
            let limit = pagination.limit.unwrap_or(entries.len());
            let start = pagination.cursor.as_ref().map_or(0, |cursor| {
                entries
                    .iter()
                    .position(|e| e.cid().unwrap_or_default() == cursor.message_cid)
                    .unwrap_or(0)
            });

            let mut end = start + limit + 1;
            if end > entries.len() {
                end = entries.len();
            }
            entries = entries[start..end].to_vec();
        }

        Ok(entries)
    }

    // This query strategy is used when the filter will return a larger set of
    // results.
    async fn query_full(&self, query: &RecordsQuery) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        let (limit, cursor) =
            query.pagination.as_ref().map_or((None, None), |p| (p.limit, p.cursor.as_ref()));

        // the location in the index to begin querying from
        let start_key =
            cursor.map_or(Unbounded, |c| Included(format!("{}{NULL}{}", c.value, c.message_cid)));
        let index = self.get(&query.sort.to_string()).await?;

        // starting from `start_key`, select matching index items until limit
        for (value, item) in index.lower_bound(start_key) {
            let Some(bytes) = self.store.get(self.owner, &item.message_cid).await? else {
                return Err(unexpected!("entry not found"));
            };
            let entry = block::decode(&bytes)?;

            // match entry against any filter
            for filter in &query.filters {
                if filter.is_match(&entry) {
                    entries.push(entry);
                    break;
                }
            }

            // stop when page limit + 1 is reached
            if let Some(lim) = limit {
                if entries.len() == lim + 1 {
                    break;
                }
            }
        }

        Ok(entries)
    }

    async fn query_protocols(&self, query: &ProtocolsQuery) -> Result<Vec<Entry>> {
        let mut results = BTreeMap::new();

        let index = self.get("protocol").await?;
        for item in index.items.values() {
            let Some(bytes) = self.store.get(self.owner, &item.message_cid).await? else {
                return Err(unexpected!("entry not found"));
            };
            let entry: Entry = block::decode(&bytes)?;

            let Some(configure) = entry.as_configure() else {
                continue;
            };

            // check for filter match
            if let Some(protocol) = &query.protocol {
                if configure.descriptor.definition.protocol != *protocol {
                    continue;
                }
            }
            if let Some(published) = &query.published {
                if configure.descriptor.definition.published != *published {
                    continue;
                }
            }

            // sort results as we collect using `message_cid` as a tie-breaker
            let sort_key = format!("{}{}", &item.fields["messageTimestamp"], item.message_cid);
            results.insert(sort_key, entry);
        }

        Ok(results.values().cloned().collect())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    field: String,
    items: BTreeMap<String, IndexItem>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct IndexItem {
    message_cid: String,
    fields: HashMap<String, String>,
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

    fn lower_bound(&self, lower: Bound<String>) -> Range<String, IndexItem> {
        self.items.range((lower, Unbounded))
    }

    fn matches(&self, value: String) -> Vec<&IndexItem> {
        let index = &self.items;

        // let FilterVal::Equal(equal) = filter_val else {
        //     return vec![];
        // };

        let upper = format!("{value}{MAX}");
        index.range((Included(value), Excluded(upper))).map(|(_, item)| item).collect()

        // match filter_val {
        //     FilterVal::Equal(equal) => {
        //         let range =
        //             index.range((Included(equal.clone()), Excluded(format!("{equal}{MAX}"))));
        //         range.map(|(_, item)| item).collect()
        //     }
        //     FilterVal::OneOf(one_of) => {
        //         let mut items = vec![];

        //         for equal in one_of {
        //             let range =
        //                 index.range((Included(equal.clone()), Excluded(format!("{equal}{MAX}"))));
        //             items.extend(range.map(|(_, item)| item));
        //         }
        //         items
        //     }
        //     FilterVal::Range(range) => {
        //         let lower = range.lower.as_ref().map_or(Unbounded, |lower| match lower {
        //             Lower::Inclusive(val) => Included(val.clone()),
        //             Lower::Exclusive(val) => Excluded(format!("{val}{MAX}")),
        //         });
        //         let upper = range.upper.as_ref().map_or(Unbounded, |upper| match upper {
        //             Upper::Inclusive(val) => Included(format!("{val}{MAX}")),
        //             Upper::Exclusive(val) => Excluded(val.clone()),
        //         });
        //         let range = index.range((lower, upper));
        //         range.map(|(_, item)| item).collect()
        //     }
        // }
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
    use dwn_test::key_store::{self, ALICE_DID};
    use rand::RngCore;

    use super::*;
    use crate::clients::records::{Data, WriteBuilder};
    use crate::data::DataStream;
    use crate::store::{RecordsFilter, RecordsQuery};
    // use crate::data::MAX_ENCODED_SIZE;
    // use crate::store::block;

    #[tokio::test]
    async fn test_index() {
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
        let entries = super::query(ALICE_DID, &query, &block_store).await.unwrap();

        println!("{:?}", entries);
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
