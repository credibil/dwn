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
//! use credibil_dwn::client::records::{Data, WriteBuilder};
//! use credibil_dwn::StatusCode;
//! use reqwest;
//! use test_node::keystore;
//!
//! #[tokio::main]
//! async fn main() {
//!     let alice = keystore::new_keyring();
//!
//!     // create a message to write a record
//!     let write = WriteBuilder::new()
//!         .data(Data::from(b"a new write record".to_vec()))
//!         .sign(&alice)
//!         .build()
//!         .await
//!         .expect("should create write");
//!
//!     // send the request to a DWN node
//!     let client = reqwest::Client::new();
//!     let reply = client.post("http://dwn.io/post").json(&write).send().await?;
//!     assert_eq!(reply.status, StatusCode::ACCEPTED);
//! }
//! ```

mod encryption;
pub mod grants;
pub mod messages;
pub mod protocols;
pub mod records;

pub use crate::interfaces::{DateRange, Pagination, Range};
