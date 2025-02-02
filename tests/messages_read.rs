//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

use std::io::{Cursor, Read};

use dwn_node::interfaces::grants::{GrantBuilder, RequestBuilder, RevocationBuilder};
use dwn_node::interfaces::messages::ReadBuilder;
use dwn_node::interfaces::protocols::ConfigureBuilder;
use dwn_node::interfaces::records::{Data, DeleteBuilder, ProtocolBuilder, WriteBuilder};
use dwn_node::permissions::Scope;
use dwn_node::interfaces::protocols::{Definition, ProtocolType, RuleSet};
use dwn_node::provider::MessageStore;
use dwn_node::store::MAX_ENCODED_SIZE;
use dwn_node::{Error, Interface, Message, Method, endpoint, store};
use http::StatusCode;
use rand::RngCore;
use test_node::key_store::{self, ALICE_DID, BOB_DID, CAROL_DID, INVALID_DID};
use test_node::provider::ProviderImpl;

// Bob should be able to read any message in Alice's web node.
#[tokio::test]
async fn read_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read any of her records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: None,
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();
    let message_cid = bob_grant.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to read one of Alice's records.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(message_cid.clone())
        .permission_grant_id(bob_grant_id)
        .build(&bob_signer)
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
    let alice_signer = key_store::signer(INVALID_DID);

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_signer)
        .await
        .expect("should create read");
    let Err(Error::Unauthorized(_)) = endpoint::handle(INVALID_DID, read, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should return a status of BadRequest (400) when the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    let mut read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_signer)
        .await
        .expect("should create read");
    read.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("schema not found"));
}

// Should return a status of BadRequest (400) when the message CID is invalid.
#[tokio::test]
async fn invalid_message_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    let mut read = ReadBuilder::new()
        // a valid message CID is required by the builder
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_signer)
        .await
        .expect("should create read");

    // set an invalid message CID
    read.descriptor.message_cid = "invalidcid".to_string();

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "invalid CID: Failed to parse multihash");
}

// Should return a status of NotFound (404) when the message cannot be found.
#[tokio::test]
async fn not_found() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .build(&alice_signer)
        .await
        .expect("should create read");

    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "message not found");
}

// Should return a status of Forbidden (401) when the owner is not the author
// (and has no grant from the owner).
#[tokio::test]
async fn forbidden() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Bob writes a record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader.clone()))
        .sign(&bob_signer)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(BOB_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to read Bob's record (and is forbidden).
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write.cid().unwrap())
        .build(&alice_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(BOB_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");
}

// Should return data less than data::MAX_ENCODED_SIZE.
#[tokio::test]
async fn data_lt_threshold() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
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
        .build(&alice_signer)
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
    let alice_signer = key_store::signer(ALICE_DID);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record, with data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid.clone())
        .build(&alice_signer)
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
    let alice_signer = key_store::signer(ALICE_DID);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
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
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::from(write)
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
        .await
        .expect("should update write");
    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the initial write expecting no data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(initial_write_cid.clone())
        .build(&alice_signer)
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
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures 2 protocols, one unpublished and the other published.
    // --------------------------------------------------
    // unpublished
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://unpublished.xyz"))
        .build(&alice_signer)
        .await
        .expect("should build");

    let unpublished_cid = configure.cid().expect("should get CID");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // published
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://published.xyz").published(true))
        .build(&alice_signer)
        .await
        .expect("should build");

    let published_cid = configure.cid().expect("should get CID");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read a message protected by the protocol.
    // --------------------------------------------------
    // unpublished
    let read = ReadBuilder::new()
        .message_cid(&unpublished_cid)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");

    // published
    let read = ReadBuilder::new()
        .message_cid(&published_cid)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");

    // --------------------------------------------------
    // Alice reads both published and unpublished protocols.
    // --------------------------------------------------
    // unpublished
    let read = ReadBuilder::new()
        .message_cid(&unpublished_cid)
        .build(&alice_signer)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, unpublished_cid);

    // published
    let read = ReadBuilder::new()
        .message_cid(&published_cid)
        .build(&alice_signer)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, published_cid);
}

// Should return a status of Forbidden (403) when grant has different interface scope.
#[tokio::test]
async fn invalid_interface() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    // unpublished
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record for Bob to read.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission read a `RecordsWrite` message protected by
    // the `http://minimal.xyz` protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to try and read the message and fails because the
    // message does not have the protocol allowed by the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid)
        .permission_grant_id(bob_grant_id)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should allow external parties to read a message using a n unrestricted grant.
#[tokio::test]
async fn permissive_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice writes a record for Bob to read.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read any record.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: None,
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .permission_grant_id(bob_grant_id)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, write_cid);
}

// Should allow reading protocol messages with a protocol-based grant.
#[tokio::test]
async fn protocol_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);
    let carol_signer = key_store::signer(CAROL_DID);

    // --------------------------------------------------
    // Alice configures an unpublished protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .build(&alice_signer)
        .await
        .expect("should build");

    let alice_configure_cid = configure.cid().expect("should get CID");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol requests permission to write records for the protocol.
    // --------------------------------------------------
    let carol_request = RequestBuilder::new()
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .build(&carol_signer)
        .await
        .expect("should create grant");

    let carol_request_cid = carol_request.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, carol_request, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Carol permission to write records for the protocol.
    // --------------------------------------------------
    let carol_grant = GrantBuilder::new()
        .granted_to(CAROL_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let carol_grant_cid = carol_grant.cid().expect("should get CID");

    let reply =
        endpoint::handle(ALICE_DID, carol_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record associated with the protocol.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let alice_write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes a record associated with the protocol.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_signer)
        .await
        .expect("should create delete");

    let alice_delete_cid = delete.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol writes a record associated with the protocol.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(&carol_grant.record_id)
        .sign(&carol_signer)
        .build()
        .await
        .expect("should create write");

    let carol_write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice revokes Carol's grant.
    // --------------------------------------------------
    let carol_revocation = RevocationBuilder::new()
        .grant(carol_grant)
        .build(&alice_signer)
        .await
        .expect("should create revocation");

    let carol_revocation_cid = carol_revocation.cid().expect("should get CID");

    let reply =
        endpoint::handle(ALICE_DID, carol_revocation, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .delegated(false)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob cannot read Alice's messages without permission.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&alice_write_cid)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");

    // --------------------------------------------------
    // Bob can read all messages associated with the grant.
    // --------------------------------------------------
    // Alice's protocol configuration
    let mut read = ReadBuilder::new()
        .message_cid(&alice_configure_cid)
        .permission_grant_id(&bob_grant.record_id)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_configure_cid);

    // Carol's permission request
    read.descriptor.message_cid = carol_request_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_request_cid);

    // Alice's Permission Grant to Carol
    read.descriptor.message_cid = carol_grant_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_grant_cid);

    // Alice's write
    read.descriptor.message_cid = alice_write_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_write_cid);

    // Alice's delete
    read.descriptor.message_cid = alice_delete_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_delete_cid);

    // Carol's write
    read.descriptor.message_cid = carol_write_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_write_cid);

    // Alice's Revocation of Carol's Grant
    read.descriptor.message_cid = carol_revocation_cid.clone();

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    let body = reply.body.expect("should have body");
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_revocation_cid);

    // --------------------------------------------------
    // CONTROL: Alice writes a record not associated with the protocol
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // Bob is unable to read the control message
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");
}

// Should reject reading protocol messages with mismatching protocol grant scopes.
#[tokio::test]
async fn invalid_protocol_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record associated with the protocol.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages for the protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let grant_cid = bob_grant.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to use the grant to read the protocol message, but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .permission_grant_id(grant_cid)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no grant found");
}

// Should fail if a `RecordsWrite` message is not found for a requested `RecordsDelete`.
#[tokio::test]
async fn delete_with_no_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages for the protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds a delete record directly into the database.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_signer)
        .await
        .expect("should create write");

    let entry = store::Entry::from(&delete);
    MessageStore::put(&provider, ALICE_DID, &entry).await.expect("should put message");

    // --------------------------------------------------
    // Bob attempts to use the grant to read the protocol message, but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&delete.cid().expect("should get CID"))
        .permission_grant_id(bob_grant_id)
        .build(&bob_signer)
        .await
        .expect("should create read");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "expected `RecordsWrite` message");
}
