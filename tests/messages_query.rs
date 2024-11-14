//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use http::StatusCode;
// use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_utils::store::ProviderImpl;
use vercre_dwn::data_stream::DataStream;
use vercre_dwn::handlers::{configure, write};
use vercre_dwn::messages::{query, read, QueryBuilder, ReadBuilder};
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData};
use vercre_dwn::Message;

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

// Use owner signature for authorization when it is provided.
#[tokio::test]
async fn all_messages() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("protocols/allow_any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let mut expected_cids = vec![configure.cid().unwrap()];

    let reply = configure::handle(ALICE_DID, configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 5 records.
    // --------------------------------------------------
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");
    let schema = definition.types["post"].schema.clone().expect("should have schema");
    let protocol = write::WriteProtocol {
        protocol: definition.protocol.clone(),
        protocol_path: "post".to_string(),
    };

    let reader = DataStream::from(data);

    for _i in 1..=5 {
        let message = WriteBuilder::new()
            .protocol(protocol.clone())
            .schema(&schema)
            // .data(WriteData::Bytes { data: data.clone() })
            .data(WriteData::Reader {
                reader: reader.clone(),
            })
            .published(true)
            .build(&alice_keyring)
            .await
            .expect("should create write");

        expected_cids.push(message.cid().unwrap());

        let reply = write::handle(ALICE_DID, message, &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for messages without a cursor, and expects to see
    // all 5 records as well as the protocol configuration message.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    let reply = query::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let Some(entries) = reply.entries else {
        panic!("should have entries");
    };
    assert_eq!(entries.len(), 6);

    for entry in entries {
        assert!(expected_cids.contains(&entry));
    }

    // --------------------------------------------------
    // Alice writes an additional record.
    // --------------------------------------------------
    let message = WriteBuilder::new()
        .protocol(protocol.clone())
        .schema(&schema)
        // .data(WriteData::Bytes { data: data.clone() })
        .data(WriteData::Reader { reader })
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    expected_cids.push(message.cid().unwrap());

    let reply = write::handle(ALICE_DID, message, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for messages beyond the cursor, and
    // expects to see only the additional record.
    // --------------------------------------------------
    // TODO: implement cursor
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create query");
    let reply = query::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let Some(entries) = reply.entries else {
        panic!("should have entries");
    };
    assert_eq!(entries.len(), 7);

    // --------------------------------------------------
    // Alice reads one of the returned messages.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&entries[0])
        .build(&alice_keyring)
        .await
        .expect("should create read");
    let reply = read::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    // assert_snapshot!("read", reply, {
    //     ".entry.message.descriptor.messageTimestamp" => "[messageTimestamp]",
    // });
}
