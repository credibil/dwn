//! # Index Store
//!
//! The index store is responsible for storing and retrieving message indexes.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound::{Excluded, Included, Unbounded};

use serde::{Deserialize, Serialize};

use crate::provider::BlockStore;
use crate::store::{Entry, FilterVal, Query, RecordsFilter, RecordsQuery, Sort, block};
use crate::{Lower, Result, Upper, unexpected};

const SEPARATOR: u8 = 0x00;

pub async fn insert(owner: &str, entry: &Entry, store: &impl BlockStore) -> Result<()> {
    let message_cid = entry.cid()?;
    let write = entry.as_write().unwrap();
    let fields = write.indexes();

    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    for (field, value) in fields {
        let mut index = indexes.get(&field).await?;
        index.insert(value.as_str().unwrap(), &message_cid);
        indexes.update(index).await?;
    }

    // TODO: add reverse lookup for deletes: {"message_cid": fields[]}
    // index.insert(message_cid, &indexes);

    Ok(())
}

pub async fn query(owner: &str, query: &Query, store: &impl BlockStore) -> Result<Vec<Entry>> {
    let indexes = IndexesBuilder::new().owner(owner).store(store).build();

    let Query::Records(rq) = query else {
        return Err(unexpected!("unsupported query type"));
    };

    let concise = true;
    for filter in &rq.filters {
        // if !filter.is_concise() {
        //  concise = false;
        //  break;
        // }
    }

    // choose strategy for query
    let entries = if concise {
        indexes.query_concise(rq).await?
    } else {
        indexes.query_full(&rq.filters).await?
    };

    Ok(entries)
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
        let mut matches = HashMap::new();

        for filter in &query.filters {
            // determine the best index to use for the filter
            let Some((index, filter_val)) = filter.optimize() else {
                continue;
            };
            let index = self.get(index).await?;

            // 1. narrow index values to one or more sets of candidate matches
            // 2. iterate over subsets comparing each entry with the full filter
            for range in index.matches(&filter_val) {
                for (index_val, message_cid) in range {
                    // short circuit when previously matched
                    if matches.contains_key(message_cid) {
                        continue;
                    }

                    // TODO: save indexable fields with each index entry to
                    // avoid retrieving the entry unnecessarily

                    // use full entry to  match against other filter properties
                    let Some(bytes) = self.store.get(self.owner, message_cid).await? else {
                        return Err(unexpected!("entry not found"));
                    };
                    let entry = block::decode(&bytes)?;
                    if filter.is_match(&entry) {
                        matches.insert(message_cid.clone(), entry);
                    }
                }
            }
        }

        // sort (sort property & direction)
        let mut entries = matches.values().cloned().collect::<Vec<Entry>>();

        entries.sort_by(|a, b| {
            let write_a = a.as_write().unwrap();
            let write_b = b.as_write().unwrap();

            match query.sort {
                Some(Sort::CreatedAscending) => {
                    write_a.descriptor.date_created.cmp(&write_b.descriptor.date_created)
                }
                Some(Sort::CreatedDescending) => {
                    write_b.descriptor.date_created.cmp(&write_a.descriptor.date_created)
                }
                Some(Sort::PublishedAscending) => {
                    write_a.descriptor.date_published.cmp(&write_b.descriptor.date_published)
                }
                Some(Sort::PublishedDescending) => {
                    write_b.descriptor.date_published.cmp(&write_a.descriptor.date_published)
                }
                Some(Sort::TimestampDescending) => write_b
                    .descriptor
                    .base
                    .message_timestamp
                    .cmp(&write_a.descriptor.base.message_timestamp),

                // otherwise, Sort::TimestampAscending
                _ => write_a
                    .descriptor
                    .base
                    .message_timestamp
                    .cmp(&write_b.descriptor.base.message_timestamp),
            }
        });

        // paging

        Ok(entries)
    }

    // This query strategy is used when the filter will return a larger set of
    // results.
    async fn query_full(&self, filters: &[RecordsFilter]) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();

        for filter in filters {
            if let Some(published) = &filter.published {
                let index = self.get("data_format").await?;
                for (value, message_cid) in index.values {
                    if value == "application/json" {
                        let bytes = self.store.get(self.owner, &message_cid).await?.unwrap();
                        let entry: Entry = block::decode(&bytes)?;
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    field: String,
    values: BTreeMap<String, String>,
}

impl Index {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            values: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, value: impl Into<String>, message_cid: impl Into<String>) {
        self.values.insert(value.into(), message_cid.into());
    }

    fn matches<'a>(&'a self, filter_val: &FilterVal) -> Vec<Range<'a, String, String>> {
        let index = &self.values;

        match filter_val {
            FilterVal::Equal(equal) => {
                let excl = equal[..equal.len() - 1].to_string();
                let range = index.range((Excluded(excl), Included(equal.clone())));
                vec![range]
            }
            FilterVal::OneOf(one_of) => {
                let mut ranges = vec![];
                for equal in one_of {
                    let range = index.range((Included(equal.clone()), Included(equal.clone())));
                    ranges.push(range);
                }
                ranges
            }
            FilterVal::Range(range) => {
                let lower = range.lower.as_ref().map_or(Unbounded, |lower| match lower {
                    Lower::Inclusive(val) => Included(val.clone()),
                    Lower::Exclusive(val) => Excluded(val.clone()),
                });
                let upper = range.upper.as_ref().map_or(Unbounded, |upper| match upper {
                    Upper::Inclusive(val) => Included(val.clone()),
                    Upper::Exclusive(val) => Excluded(val.clone()),
                });
                vec![index.range((lower, upper))]
            }
        }
    }
}

pub struct IndexesBuilder<O, S> {
    owner: O,
    indexes: Option<BTreeMap<String, String>>,
    store: S,
}

/// Store not set on IndexesBuilder.
#[doc(hidden)]
pub struct NoOwner;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
pub struct Owner<'a>(&'a str);

/// Store not set on IndexesBuilder.
#[doc(hidden)]
pub struct NoStore;
/// Store has been set on IndexesBuilder.
#[doc(hidden)]
pub struct Store<'a, S: BlockStore>(&'a S);

impl IndexesBuilder<NoOwner, NoStore> {
    pub const fn new() -> Self {
        Self {
            owner: NoOwner,
            indexes: None,
            store: NoStore,
        }
    }
}

impl<S> IndexesBuilder<NoOwner, S> {
    pub fn owner(self, owner: &str) -> IndexesBuilder<Owner, S> {
        IndexesBuilder {
            owner: Owner(owner),
            indexes: None,
            store: self.store,
        }
    }
}

impl<O> IndexesBuilder<O, NoStore> {
    pub fn store<S: BlockStore>(self, store: &S) -> IndexesBuilder<O, Store<'_, S>> {
        IndexesBuilder {
            owner: self.owner,
            indexes: self.indexes,
            store: Store(store),
        }
    }
}

impl<'a, S: BlockStore> IndexesBuilder<Owner<'a>, Store<'a, S>> {
    pub fn build(self) -> Indexes<'a, S> {
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
    use crate::store::{Range, RecordsFilter, RecordsQuery};
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
                RecordsFilter::new().add_author(ALICE_DID).data_size(Range::new().gt(0).le(10)).record_id(write.record_id),
                // RecordsFilter::new().add_author(ALICE_DID),
                // RecordsFilter::new().record_id(write.record_id),
            ],
            ..Default::default()
        });
        let entries = super::query(ALICE_DID, &query, &block_store).await.unwrap();

        println!("{:?}", entries);
    }

    #[test]
    fn string_compare() {
        let a = "109";
        let b = "108";

        let a_str = format!("{a:0>8}");
        let b_str = format!("{b:0>8}");

        println!("{a_str}");
        println!("{b_str}");

        println!("{}", a_str < b_str);
    }

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
