//! # Provider

use std::io::{self, Read, Write};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use cid::Cid;
use ipld_core::ipld::Ipld;
pub use vercre_did::{DidResolver, Document};
pub use vercre_infosec::{Receiver, Signer};

use crate::data;
use crate::event::{Event, Subscriber};
use crate::store::{Cursor, block, index};
pub use crate::store::{Entry, Query};
pub use crate::tasks::ResumableTask;

/// Provider trait.
pub trait Provider:
    MessageStore + DataStore + TaskStore + EventLog + BlockStore + EventStream + DidResolver
{
}

/// `BlockStore` is used by implementers to provide data storage
/// capability.
pub trait BlockStore: Send + Sync {
    /// Store a data block in the underlying block store.
    fn put(&self, owner: &str, cid: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single block by CID from the underlying store, returning
    /// `None` if no match was found.
    fn get(&self, owner: &str, cid: &str) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Delete the data block associated with the specified CID.
    fn delete(&self, owner: &str, cid: &str) -> impl Future<Output = Result<()>> + Send;

    /// Purge all blocks from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The `MessageStore` trait is used by implementers to provide message
/// storage capability.
pub trait MessageStore: BlockStore + Sized + Send + Sync {
    /// Store a message in the underlying store.
    fn put(&self, owner: &str, entry: &Entry) -> impl Future<Output = Result<()>> + Send {
        async move {
            // store entry block
            let message_cid = entry.cid()?;
            BlockStore::delete(self, owner, &message_cid).await?;
            BlockStore::put(self, owner, &message_cid, &block::encode(entry)?).await?;

            // index entry
            Ok(index::insert(owner, entry, self).await?)
        }
    }

    /// Queries the underlying store for matches to the provided query.
    // fn query(&self, owner: &str, query: &Query) -> impl Future<Output = Result<Vec<Entry>>> + Send;
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Entry>, Option<Cursor>)>> + Send {
        async move {
            let mut results = index::query(owner, query, self).await?;

            // return cursor when paging is used
            let limit =
                query.pagination.as_ref().map(|p| p.limit.unwrap_or_default()).unwrap_or_default();

            let cursor = if limit > 0 && limit < results.len() {
                // let Query::Records(query) = query else {
                //     return Err(anyhow!("invalid query"));
                // };
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
                let Some(bytes) = BlockStore::get(self, owner, &item.message_cid).await? else {
                    return Err(anyhow!("missing block for message cid"));
                };
                entries.push(block::decode(&bytes)?);
            }

            Ok((entries, cursor))
        }
    }

    /// Fetch a single message by CID from the underlying store, returning
    /// `None` if no message was found.
    fn get(
        &self, owner: &str, message_cid: &str,
    ) -> impl Future<Output = Result<Option<Entry>>> + Send {
        async move {
            let Some(bytes) = BlockStore::get(self, owner, message_cid).await? else {
                return Ok(None);
            };
            Ok(Some(block::decode(&bytes)?))
        }
    }

    /// Delete message associated with the specified id.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async move {
            index::delete(owner, message_cid, self).await?;
            BlockStore::delete(self, owner, message_cid).await
        }
    }

    /// Purge all records from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async move { todo!("implement purge") }
    }
}

/// The `DataStore` trait is used by implementers to provide data storage
/// capability.
pub trait DataStore: BlockStore + Sized + Send + Sync {
    // /// Open a connection to the underlying store.
    // fn open(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    // /// Close the connection to the underlying store.
    // fn close(&self) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Store data in an underlying block store.
    ///
    /// The default implementation uses the `BlockStore` provider for storage.
    /// This may be overridden by implementers to provide custom storage.
    fn put(
        &self, owner: &str, _record_id: &str, data_cid: &str, data: impl Read + Send,
    ) -> impl Future<Output = anyhow::Result<(String, usize)>> + Send {
        async move {
            let mut links = vec![];
            let mut byte_count = 0;
            let mut data = data;

            // read data stream in chunks, storing each chunk as an IPLD block
            loop {
                let mut buffer = [0u8; data::CHUNK_SIZE];
                if let Ok(bytes_read) = data.read(&mut buffer[..]) {
                    if bytes_read == 0 {
                        break;
                    }
                    // encode buffer to IPLD block
                    let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
                    let block = block::Block::encode(&ipld)?;

                    // insert into the blockstore
                    let cid = block.cid();
                    BlockStore::put(self, owner, cid, block.data()).await?;

                    // save link to block
                    let cid = Cid::from_str(cid)?;
                    links.push(Ipld::Link(cid));
                    byte_count += bytes_read;
                }
            }

            // create a root block linking to the data blocks
            let block = block::Block::encode(&Ipld::List(links))?;
            BlockStore::put(self, owner, data_cid, block.data()).await?;

            // // confirm that the root block's CID matches the provided data CID
            // if data_cid != block.cid() {
            //     return Err(anyhow!("data cid mismatch"));
            // }

            Ok((block.cid().to_string(), byte_count))
        }
    }

    /// Fetches a single message by CID from an underlying block store.
    fn get(
        &self, owner: &str, _record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send {
        async move {
            // get root block
            let Some(bytes) = BlockStore::get(self, owner, data_cid).await? else {
                return Ok(None);
            };

            // the root blook contains a list of links to data blocks
            let Ipld::List(links) = block::decode(&bytes)? else {
                return Ok(None);
            };

            // TODO: optimize by streaming the data blocks as fetched
            // fetch each data block
            let mut buf = io::Cursor::new(vec![]);

            for link in links {
                // get data block
                let Ipld::Link(link_cid) = link else {
                    return Err(anyhow!("invalid link"));
                };
                let Some(bytes) = BlockStore::get(self, owner, &link_cid.to_string()).await? else {
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
    }

    /// Delete data associated with the specified id.
    fn delete(
        &self, owner: &str, _record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async move { BlockStore::delete(self, owner, data_cid).await }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = anyhow::Result<()>> + Send {
        async move { todo!("implement purge") }
    }
}

/// The `TaskStore` trait is used by implementers to provide data storage
/// capability.
pub trait TaskStore: BlockStore + Sized + Send + Sync {
    /// Registers a new resumable task that is currently in-flight/under
    /// processing to the store.
    ///
    /// If the task has timed out, a client will be able to grab it through the
    /// `grab()` method and resume the task.
    fn register(
        &self, _owner: &str, _task: &ResumableTask, _timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async move { Ok(()) }
    }

    /// Grabs `count` unhandled tasks from the store.
    ///
    /// Unhandled tasks are tasks that are not currently in-flight/under processing
    /// (ie. tasks that have timed-out).
    ///
    /// N.B.: The implementation must make sure that once a task is grabbed by a client,
    /// tis timeout must be updated so that it is considered in-flight/under processing
    /// and cannot be grabbed by another client until it is timed-out.
    fn grab(
        &self, _owner: &str, _count: u64,
    ) -> impl Future<Output = Result<Vec<ResumableTask>>> + Send {
        async move { todo!() }
    }

    /// Reads the task associated with the task ID provided regardless of whether
    /// it is in-flight/under processing or not.
    ///
    /// This is mainly introduced for testing purposes: ie. to check the status of
    /// a task for easy test verification.
    fn read(
        &self, _owner: &str, _task_id: &str,
    ) -> impl Future<Output = Result<Option<ResumableTask>>> + Send {
        async move { todo!() }
    }

    /// Extends the timeout of the task associated with the task ID provided.
    ///
    /// No-op if the task is not found, as this implies that the task has already
    /// been completed. This allows the client that is executing the task to
    /// continue working on it before the task is considered timed out.
    fn extend(
        &self, _owner: &str, _task_id: &str, _timeout_secs: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }

    /// Delete data associated with the specified id.
    fn delete(&self, _owner: &str, _task_id: &str) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }

    /// Purge all data from the store.
    fn purge(&self, _owner: &str) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }
}

/// The `Metadata` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventLog: BlockStore + Sized + Send + Sync {
    /// Adds a message event to a owner's event log.
    fn append(&self, owner: &str, event: &Event) -> impl Future<Output = Result<()>> + Send {
        async move {
            // store entry block
            let message_cid = event.cid()?;
            BlockStore::delete(self, owner, &message_cid).await?;
            BlockStore::put(self, owner, &message_cid, &block::encode(event)?).await?;

            // index entry
            // TODO: add watermark to indexes
            // const watermark = this.ulidFactory();
            Ok(index::insert(owner, event, self).await?)
        }
    }

    /// Retrieves all of a owner's events that occurred after the cursor provided.
    /// If no cursor is provided, all events for a given owner will be returned.
    ///
    /// The cursor is a `message_cid`.
    fn events(
        &self, _owner: &str, _cursor: Option<Cursor>,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send {
        async move { todo!() }
    }

    /// Retrieves a filtered set of events that occurred after a the cursor
    /// provided, accepts multiple filters. If no cursor is provided, all
    /// events for a given owner and filter combo will be returned. The cursor
    /// is a `message_cid`.
    ///
    /// Returns an array of `message_cid`s that represent the events.
    fn query(
        &self, owner: &str, query: &Query,
    ) -> impl Future<Output = Result<(Vec<Event>, Option<Cursor>)>> + Send {
        async move {
            let mut results = index::query(owner, query, self).await?;

            // return cursor when paging is used
            let limit =
                query.pagination.as_ref().map(|p| p.limit.unwrap_or_default()).unwrap_or_default();

            let cursor = if limit > 0 && limit < results.len() {
                // set cursor to the last item remaining after the spliced result.
                results.pop().map(|item| Cursor {
                    message_cid: item.message_cid.clone(),
                    value: item.fields["messageTimestamp"].clone(),
                })
            } else {
                None
            };

            let mut entries = Vec::new();
            for item in results {
                let Some(bytes) = BlockStore::get(self, owner, &item.message_cid).await? else {
                    return Err(anyhow!("missing block for message cid"));
                };
                entries.push(block::decode(&bytes)?);
            }

            Ok((entries, cursor))
        }
    }

    /// Deletes event for the specified `message_cid`.
    fn delete(&self, owner: &str, message_cid: &str) -> impl Future<Output = Result<()>> + Send {
        async move {
            index::delete(owner, message_cid, self).await?;
            BlockStore::delete(self, owner, message_cid).await
        }
    }

    /// Purge all data from the store.
    fn purge(&self) -> impl Future<Output = Result<()>> + Send {
        async move { todo!() }
    }
}

/// The `EventStream` trait is used by implementers to provide `Client`, `Issuer`,
/// and `Server` metadata to the library.
pub trait EventStream: Send + Sync {
    /// Subscribes to an owner's event stream.
    fn subscribe(&self, owner: &str) -> impl Future<Output = Result<Subscriber>> + Send;

    /// Emits an event to a owner's event stream.
    fn emit(&self, owner: &str, event: &Event) -> impl Future<Output = Result<()>> + Send;
}
