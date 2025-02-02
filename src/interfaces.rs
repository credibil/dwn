//! # Interfaces
//!
//! Interfaces are the main building blocks of the system. They define the
//! structure of the data that is exchanged between users and the DWN.
//!
//! The three primary interfaces are `Records`, `Protocols`, and `Messages`
//! with each having a subset of `Methods` that define the operations that can
//! be performed on the data.
//!
//! Interface methods are executed by sending JSON messages to the DWN which,
//! in turn, will respond with a JSON reply. This library provides the tools
//! to easily create and parse these messages.
//!
//! ## Example Usage
//!
//! The following example demonstrates how to write a record to the DWN.
//!
//! ```rust
//! use base64ct::{Base64UrlUnpadded, Encoding};
//! use dwn_node::interfaces::records::{Data, QueryBuilder, RecordsFilter, WriteBuilder};
//! use dwn_node::{StatusCode, endpoint};
//! use test_node::key_store::{self, ALICE_DID};
//! use test_node::provider::ProviderImpl;
//!
//! #[tokio::main]
//! async fn main() {
//!     let provider = ProviderImpl::new().await.expect("should create provider");
//!     let alice_signer = key_store::signer(ALICE_DID);
//!
//!     let write = WriteBuilder::new()
//!         .data(Data::from(b"a new write record".to_vec()))
//!         .sign(&alice_signer)
//!         .build()
//!         .await
//!         .expect("should create write");
//!     let reply =
//!         endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
//!     assert_eq!(reply.status.code, StatusCode::ACCEPTED);
//!
//!     // and to read the previously written record:
//!
//!     let query = QueryBuilder::new()
//!         .filter(RecordsFilter::new().record_id(&write.record_id))
//!         .sign(&alice_signer)
//!         .build()
//!         .await
//!         .expect("should create read");
//!     let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
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

pub mod grants;
pub mod messages;
pub mod protocols;
pub mod records;
