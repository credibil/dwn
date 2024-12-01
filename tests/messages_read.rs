//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

use std::io::Read;

use dwn_test::key_store::{ALICE_DID, BOB_DID, INVALID_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::messages::ReadBuilder;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData};
use vercre_dwn::{Error, Interface, Message, Method, endpoint};

// Bob should be able to read any message in Alice's web node.
#[tokio::test]
async fn read_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice issues a grant allowing Bob to read any record in her web node.
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB_DID)
        .request_id("grant_id_1")
        .description("allow Bob to read messages")
        .expires_in(60 * 60 * 24)
        .scope(Interface::Messages, Method::Read, None);
    let bob_grant = builder.build(&alice_keyring).await.expect("should create grant");

    let record_id = bob_grant.record_id.clone();
    let message_cid = bob_grant.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    println!("{message_cid}");

    // --------------------------------------------------
    // Bob invokes the grant to read a record from Alice's web node.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(message_cid.clone())
        .permission_grant_id(record_id)
        .build(&bob_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, message_cid);
}

// Should returns Unauthenticated (401) when authentication fails.
#[tokio::test]
async fn invalid_signature() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(INVALID_DID).expect("should get an ivalid keyring");

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_keyring)
        .await
        .expect("should create read");
    let Err(Error::Unauthorized(_)) = endpoint::handle(INVALID_DID, read, &provider).await else {
        panic!("should not be authorized");
    };
}

// Should return a status of BadRequest (400) when the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_keyring)
        .await
        .expect("should create read");
    read.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be a bad request");
    };
}

// Should return a status of BadRequest (400) when the message CID is invalid.
#[tokio::test]
async fn invalid_message_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut read = ReadBuilder::new()
        // a valid message CID is required by the builder
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    // set an invalid message CID
    read.descriptor.message_cid = "invalidcid".to_string();

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be a bad request");
    };
}

// Should return a status of NotFound (404) when the message cannot be found.
#[tokio::test]
async fn not_found() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let Err(Error::NotFound(_)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be a not found");
    };
}

// Should return a status of Forbidden (401) when the owner is not the author
// (and has no grant from the owner).
#[tokio::test]
async fn forbidden() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Bob writes a record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader.clone()))
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(BOB_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to read Bob's record (and is forbidden).
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write.cid().unwrap())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(_)) = endpoint::handle(BOB_DID, read, &provider).await else {
        panic!("should be a not found");
    };
}

// Should return data less than threshold.
#[tokio::test]
async fn data_lt_max() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record with data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid.clone())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, write_cid);

    let mut stream = entry.data.expect("should have data");
    let mut data_bytes = Vec::new();
    stream.read_to_end(&mut data_bytes).expect("should read data");
    assert_eq!(data_bytes, data);
}
