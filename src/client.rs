//! # Client
//!
//! The `client` module exposes data structures and functions for use by DWN
//! clients. Primarily, this means builders for creating and signing messages
//! to be sent to a DWN node.
//!
//! ## Example Usage
//!
//! The following example demonstrates how to write and query for a DWN record.
//!
//! ```rust
//! use base64ct::{Base64UrlUnpadded, Encoding};
//! use credibil_dwn::client::records::{Data, QueryBuilder, RecordsFilter, WriteBuilder};
//! use credibil_dwn::{StatusCode, endpoint};
//! use test_node::keystore;
//! use test_node::provider::ProviderImpl;
//!
//! #[tokio::main]
//! async fn main() {
//!     let provider = ProviderImpl::new().await.expect("should create provider");
//!     let alice = keystore::new_keyring();
//!
//!     let write = WriteBuilder::new()
//!         .data(Data::from(b"a new write record".to_vec()))
//!         .sign(&alice)
//!         .build()
//!         .await
//!         .expect("should create write");
//!     let reply =
//!         endpoint::handle(&alice.did, write.clone(), &provider).await.expect("should write");
//!     assert_eq!(reply.status.code, StatusCode::ACCEPTED);
//!
//!     // and to read the previously written record:
//!     let query = QueryBuilder::new()
//!         .filter(RecordsFilter::new().record_id(&write.record_id))
//!         .sign(&alice)
//!         .build()
//!         .await
//!         .expect("should create read");
//!     let reply = endpoint::handle(&alice.did, query, &provider).await.expect("should write");
//!     assert_eq!(reply.status.code, StatusCode::OK);
//!
//!     let body = reply.body.expect("should have body");
//!     let entries = body.entries.expect("should have entries");
//!     assert_eq!(entries.len(), 1);
//!     assert_eq!(
//!         entries[0].write.encoded_data,
//!         Some(Base64UrlUnpadded::encode_string(b"a new write record"))
//!     );
//! }
//! ```

mod encryption;
pub mod grants;
pub mod messages;
pub mod protocols;
pub mod records;

pub use crate::interfaces::{DateRange, Pagination, Range};
