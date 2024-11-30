//! Message Query
//!
//! This test demonstrates how a web node owner create messages and
//! subsequently query for them.

use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use serde_json::json;
use vercre_dwn::data::DataStream;
use vercre_dwn::messages::{QueryBuilder, ReadBuilder};
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData, WriteProtocol};
use vercre_dwn::{Error, Interface, Message, endpoint};

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn all_owner_messages() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let mut expected_cids = vec![configure.cid().unwrap()];

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 5 records.
    // --------------------------------------------------
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");
    let schema = definition.types["post"].schema.clone().expect("should have schema");
    let protocol = WriteProtocol {
        protocol: definition.protocol.clone(),
        protocol_path: "post".to_string(),
    };

    let reader = DataStream::from(data);

    for _i in 1..=5 {
        let write = WriteBuilder::new()
            .protocol(protocol.clone())
            .schema(&schema)
            .data(WriteData::Reader(reader.clone()))
            .published(true)
            .build(&alice_keyring)
            .await
            .expect("should create write");

        expected_cids.push(write.cid().unwrap());

        let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for messages without a cursor, and expects to see
    // all 5 records as well as the protocol configuration message.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
    let entries = query_reply.entries.expect("should have entries");
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
        .data(WriteData::Reader(reader))
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    expected_cids.push(message.cid().unwrap());

    let reply = endpoint::handle(ALICE_DID, message, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for messages beyond the cursor, and
    // expects to see only the additional record.
    // --------------------------------------------------
    // TODO: implement cursor
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 7);

    // --------------------------------------------------
    // Alice reads one of the returned messages.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&entries[0])
        .build(&alice_keyring)
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
}

// Should return a status of Forbidden (403) if the requestor is not the owner
// and has no permission grant.
#[tokio::test]
async fn no_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    let Err(Error::Forbidden(_)) = endpoint::handle(BOB_DID, query, &provider).await else {
        panic!("should not be authorized");
    };
}

// Should return a status of BadRequest (400) if the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    query.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be a bad request");
    };
}

// Should return a status of BadRequest (400) if an empty filter is provided.
// N.B. Code comments are at odds with this test.
#[tokio::test]
#[ignore]
async fn empty_filter() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    query.descriptor.filters = vec![];

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be a bad request");
    };
}
