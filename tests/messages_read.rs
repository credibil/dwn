//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

#![cfg(all(feature = "client", feature = "server"))]

use std::io::{Cursor, Read};

use credibil_dwn::api::Client;
use credibil_dwn::client::grants::{GrantBuilder, RequestBuilder, RevocationBuilder, Scope};
use credibil_dwn::client::messages::ReadBuilder;
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
use credibil_dwn::client::records::{Data, DeleteBuilder, ProtocolBuilder, WriteBuilder};
use credibil_dwn::interfaces::messages::ReadReply;
use credibil_dwn::provider::MessageStore;
use credibil_dwn::store::MAX_ENCODED_SIZE;
use credibil_dwn::{Error, Interface, Method, StatusCode};
use rand::RngCore;
use test_utils::{Identity, Provider};
use tokio::sync::OnceCell;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static CAROL: OnceCell<Identity> = OnceCell::const_new();
static NODE: OnceCell<Client<Provider>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("messages_read_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("messages_read_bob").await }).await
}
async fn carol() -> &'static Identity {
    CAROL.get_or_init(|| async { Identity::new("messages_read_carol").await }).await
}
async fn node() -> &'static Client<Provider> {
    NODE.get_or_init(|| async { Client::new(Provider::new().await) }).await
}

// Bob should be able to read any message in Alice's web node.
#[tokio::test]
async fn read_message() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read any of her records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();
    let message_cid = bob_grant.cid().expect("should get CID");

    let reply = node.request(bob_grant).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to read one of Alice's records.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(message_cid.clone())
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, message_cid);
}

// Should returns Unauthenticated (401) when authentication fails.
#[tokio::test]
async fn invalid_signature() {
    let invalid = Identity::invalid("invalid_signature").await;
    let invalid_client = Client::new(Provider::new().await);

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .sign(&invalid)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Unauthorized(_)) = invalid_client.request(read).owner(invalid.did()).await
    else {
        panic!("should be Unauthorized");
    };
}

// Should return a status of BadRequest (400) when the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let node = node().await;
    let alice = alice().await;

    let mut read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    read.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("schema not found"));
}

// Should return a status of BadRequest (400) when the message CID is invalid.
#[tokio::test]
async fn invalid_message_cid() {
    let node = node().await;
    let alice = alice().await;

    let mut read = ReadBuilder::new()
        // a valid message CID is required by the builder
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    // set an invalid message CID
    read.descriptor.message_cid = "invalidcid".to_string();

    let Err(Error::BadRequest(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "invalid CID: Failed to parse multihash");
}

// Should return a status of NotFound (404) when the message cannot be found.
#[tokio::test]
async fn not_found() {
    let node = node().await;
    let alice = alice().await;

    let read = ReadBuilder::new()
        .message_cid("bafkreihxrkspxsocoaoetqjm3iop26svz2k622cgart56v2ng7g6q6ofwa".to_string())
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let Err(Error::NotFound(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "message not found");
}

// Should return a status of Forbidden (401) when the owner is not the author
// (and has no grant from the owner).
#[tokio::test]
async fn forbidden() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Bob writes a record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader.clone()))
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write.clone()).owner(bob.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to read Bob's record (and is forbidden).
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write.cid().unwrap())
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(bob.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");
}

// Should return data less than data::MAX_ENCODED_SIZE.
#[tokio::test]
async fn data_lt_threshold() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record with data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid.clone())
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let body: ReadReply = reply.body;
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
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::rng().fill_bytes(&mut data);
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record, with data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid.clone())
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let body: ReadReply = reply.body;
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
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::rng().fill_bytes(&mut data);
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let initial_write_cid = write.cid().expect("should get CID");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::rng().fill_bytes(&mut data);
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::from(write)
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should update write");
    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the initial write expecting no data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(initial_write_cid.clone())
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, initial_write_cid);

    assert!(entry.data.is_none());
}

// Should return a status of Forbidden (403) if the owner is not the author.
#[tokio::test]
async fn owner_not_author() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures 2 protocols, one unpublished and the other published.
    // --------------------------------------------------
    // unpublished
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://unpublished.xyz"))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let unpublished_cid = configure.cid().expect("should get CID");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // published
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://published.xyz").published(true))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let published_cid = configure.cid().expect("should get CID");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read a message protected by the protocol.
    // --------------------------------------------------
    // unpublished
    let read = ReadBuilder::new()
        .message_cid(&unpublished_cid)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");

    // published
    let read = ReadBuilder::new()
        .message_cid(&published_cid)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");

    // --------------------------------------------------
    // Alice reads both published and unpublished protocols.
    // --------------------------------------------------
    // unpublished
    let read = ReadBuilder::new()
        .message_cid(&unpublished_cid)
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, unpublished_cid);

    // published
    let read = ReadBuilder::new()
        .message_cid(&published_cid)
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, published_cid);
}

// Should return a status of Forbidden (403) when grant has different interface scope.
#[tokio::test]
async fn invalid_interface() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    // unpublished
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record for Bob to read.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission read a `RecordsWrite` message protected by
    // the `http://minimal.xyz` protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = node.request(bob_grant).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to try and read the message and fails because the
    // message does not have the protocol allowed by the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(write_cid)
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should allow external parties to read a message using a n unrestricted grant.
#[tokio::test]
async fn permissive_grant() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record for Bob to read.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read any record.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = node.request(bob_grant).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, write_cid);
}

// Should allow reading protocol messages with a protocol-based grant.
#[tokio::test]
async fn protocol_grant() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures an unpublished protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let alice_configure_cid = configure.cid().expect("should get CID");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol requests permission to write records for the protocol.
    // --------------------------------------------------
    let carol_request = RequestBuilder::new()
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .sign(carol)
        .build()
        .await
        .expect("should create grant");

    let carol_request_cid = carol_request.cid().expect("should get CID");

    let reply = node.request(carol_request).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Carol permission to write records for the protocol.
    // --------------------------------------------------
    let carol_grant = GrantBuilder::new()
        .granted_to(carol.did())
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let carol_grant_cid = carol_grant.cid().expect("should get CID");

    let reply = node.request(carol_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let alice_write_cid = write.cid().expect("should get CID");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes a record associated with the protocol.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let alice_delete_cid = delete.cid().expect("should get CID");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(carol)
        .build()
        .await
        .expect("should create write");

    let carol_write_cid = write.cid().expect("should get CID");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice revokes Carol's grant.
    // --------------------------------------------------
    let carol_revocation = RevocationBuilder::new()
        .grant(carol_grant)
        .sign(alice)
        .build()
        .await
        .expect("should create revocation");

    let carol_revocation_cid = carol_revocation.cid().expect("should get CID");

    let reply = node.request(carol_revocation).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .delegated(false)
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let reply = node.request(bob_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob cannot read Alice's messages without permission.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&alice_write_cid)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
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
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_configure_cid);

    // Carol's permission request
    read.descriptor.message_cid = carol_request_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_request_cid);

    // Alice's Permission Grant to Carol
    read.descriptor.message_cid = carol_grant_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_grant_cid);

    // Alice's write
    read.descriptor.message_cid = alice_write_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_write_cid);

    // Alice's delete
    read.descriptor.message_cid = alice_delete_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, alice_delete_cid);

    // Carol's write
    read.descriptor.message_cid = carol_write_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_write_cid);

    // Alice's Revocation of Carol's Grant
    read.descriptor.message_cid = carol_revocation_cid.clone();

    let reply = node.request(read.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    let body: ReadReply = reply.body;
    let entry = body.entry.expect("should have entry");
    assert_eq!(entry.message_cid, carol_revocation_cid);

    // --------------------------------------------------
    // CONTROL: Alice writes a record not associated with the protocol
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // Bob is unable to read the control message
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing grant ID");
}

// Should reject reading protocol messages with mismatching protocol grant scopes.
#[tokio::test]
async fn invalid_protocol_grant() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_cid = write.cid().expect("should get CID");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages for the protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let grant_cid = bob_grant.cid().expect("should get CID");

    let reply = node.request(bob_grant).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to use the grant to read the protocol message, but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&write_cid)
        .permission_grant_id(grant_cid)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::Forbidden(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no grant found");
}

// Should fail if a `RecordsWrite` message is not found for a requested `RecordsDelete`.
#[tokio::test]
async fn delete_with_no_write() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read messages for the protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Read,
            protocol: Some("http://minimal.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = node.request(bob_grant).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    MessageStore::put(&node.provider, alice.did(), &delete).await.expect("should put message");

    // --------------------------------------------------
    // Bob attempts to use the grant to read the protocol message, but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&delete.cid().expect("should get CID"))
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let Err(Error::BadRequest(e)) = node.request(read).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "expected `RecordsWrite` message");
}
