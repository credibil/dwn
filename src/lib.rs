//! # Decentralized Web Node (web node)

pub mod auth;
pub mod data;
pub mod endpoint;
mod error;
pub mod event;
pub mod messages;
pub mod permissions;
pub mod protocols;
pub mod provider;
pub mod records;
mod schema;
mod store;
mod utils;

use chrono::{DateTime, Utc};
use derive_more::Display;
use serde::{Deserialize, Serialize};

pub use crate::endpoint::Message;
pub use crate::error::Error;
pub use crate::provider::Provider;

/// The maximum size of a message.
pub const MAX_ENCODED_SIZE: usize = 5; //30000;

/// Result type for `DWN` handlers.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct Descriptor {
    /// The associated web node interface.
    pub interface: Interface,

    /// The interface method.
    pub method: Method,

    /// The timestamp of the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<DateTime<Utc>>,
}

/// web node interfaces.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Interface {
    #[default]
    Records,
    Protocols,
    Messages,
}

/// Interface methods.
#[derive(Clone, Debug, Default, Display, Deserialize, Serialize, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Method {
    #[default]
    Read,
    Write,
    Query,
    Configure,
    Subscribe,
    Delete,
}

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum Protocol {
    #[default]
    Http,
}

/// `Quota` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum Quota<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Default> Default for Quota<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

/// Date range filter.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DateRange {
    /// Match messages with `message_timestamp` on or after.
    pub from: String,

    /// Match messages with `message_timestamp` on or before.
    pub to: String,
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// CID of message to start from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,

    /// The number of messages to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Pagination cursor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    /// CID of message to start from.
    pub message_cid: String,

    /// The number of messages to return.
    pub value: u64,
}

#[cfg(test)]
mod stream {
    use std::fmt::Debug;
    use std::io::{self, BufRead, Read, Write};

    use super::*;

    /// Methods common to all messages.
    pub trait Stream: Send + Sync {
        fn save_data(&self) -> Result<()>;
        fn load_data(&self) -> Result<()>;
    }

    /// Records write message payload
    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MessageRecord<T>
    where
        T: BufRead + Write,
    {
        data: T,
    }

    impl<T> MessageRecord<T>
    where
        T: BufRead + Write,
    {
        pub fn new(data: T) -> Self {
            Self { data }
        }
    }

    impl<T> Stream for MessageRecord<T>
    where
        T: BufRead + Write + Serialize + Clone + Debug + Send + Sync,
    {
        // push data out of the app
        fn save_data(&self) -> Result<()> {
            let internal = vec![5, 6, 7, 8, 9];
            let mut stream = internal.as_slice();

            let mut data_stream = DataStream::new();
            data_stream.write(&mut stream).unwrap();
            println!("data pushed out: {:?}", internal);

            Ok(())
        }

        // pull data into the app
        fn load_data(&self) -> Result<()> {
            let mut data_stream = DataStream::new();

            let mut buffer = Vec::new();
            buffer.resize(5, 0);
            data_stream.read(&mut buffer).unwrap();

            // let buffer = data_stream.fill_buf().unwrap();
            println!("data pulled in: {:?}", buffer);

            Ok(())
        }
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    struct DataStream {
        data: Vec<u8>,
    }

    impl DataStream {
        fn new() -> Self {
            Self {
                data: vec![1, 2, 3, 4, 5],
            }
        }
    }

    impl BufRead for DataStream {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&self.data)
        }

        fn consume(&mut self, amt: usize) {
            self.data = self.data[amt..].to_vec();
        }
    }

    impl Read for DataStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = self.data[n..].to_vec();
            Ok(n)
        }
    }

    impl Write for DataStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_streaming() {
        let message = MessageRecord::new(DataStream::new());
        message.load_data().unwrap();
        message.save_data().unwrap();
    }
}
