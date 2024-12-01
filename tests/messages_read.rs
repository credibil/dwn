//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

use std::io::Read;

use dwn_test::key_store::{ALICE_DID, BOB_DID, INVALID_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::messages::ReadBuilder;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
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

// Should return data less than data::MAX_ENCODED_SIZE.
#[tokio::test]
async fn data_lt_threshold() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
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

// Should return data greater than data::MAX_ENCODED_SIZE.
#[tokio::test]
async fn data_gt_threshold() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
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

// Should not return data for an initial write after the record is updated.
#[tokio::test]
async fn no_data_after_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let initial_write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let reader = DataStream::from(data.to_vec());

    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .existing_write(write)
        .build(&alice_keyring)
        .await
        .expect("should update write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the initial write expecting no data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(initial_write_cid.clone())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, initial_write_cid);

    assert!(entry.data.is_none());
}

// Should return a status of Forbidden (403) if the owner is not the author.
#[tokio::test]
async fn owner_not_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures an unpublished protocol.
    // --------------------------------------------------
    let configure_unpub = ConfigureBuilder::new()
        .definition(
            Definition::new("http://unpublished.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_unpub.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a published protocol.
    // --------------------------------------------------
    let configure_pub = ConfigureBuilder::new()
        .definition(
            Definition::new("http://published.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default())
                .published(true),
        )
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_pub.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the unpublished protocol.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(configure_unpub.cid().unwrap())
        .build(&bob_keyring)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be a not found");
    };

    // --------------------------------------------------
    // Bob attempts to read the published protocol.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(configure_pub.cid().unwrap())
        .build(&bob_keyring)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be a not found");
    };

    // --------------------------------------------------
    // Alice reads both published and unpublished protocols.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(configure_pub.cid().unwrap())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, configure_pub.cid().unwrap());

    let read = ReadBuilder::new()
        .message_cid(configure_unpub.cid().unwrap())
        .build(&alice_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, configure_unpub.cid().unwrap());
}
