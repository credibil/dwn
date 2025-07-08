//! Message Query
//!
//! This test demonstrates how a web node owner create messages and
//! subsequently query for them.

#![cfg(all(feature = "client", feature = "server"))]

use std::io::Cursor;

use credibil_dwn::api::Client;
use credibil_dwn::client::grants::{GrantBuilder, Scope};
use credibil_dwn::client::messages::{MessagesFilter, QueryBuilder, ReadBuilder};
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{Data, ProtocolBuilder, WriteBuilder};
use credibil_dwn::interfaces::messages::QueryReply;
use credibil_dwn::{Error, Interface, Method, StatusCode};
use test_utils::{Identity, WebNode};
use tokio::sync::OnceCell;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static NODE: OnceCell<Client<WebNode>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("messages_query_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("messages_query_bob").await }).await
}
async fn node() -> &'static Client<WebNode> {
    NODE.get_or_init(|| async { Client::new(WebNode::new().await) }).await
}

// Should fetch all messages for owner beyond a provided cursor.
#[tokio::test]
async fn owner_messages() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let mut expected_cids = vec![configure.cid().unwrap()];

    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 5 records.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let schema = definition.types["post"].schema.clone().expect("should have schema");

    for _i in 1..=5 {
        let write = WriteBuilder::new()
            .protocol(ProtocolBuilder {
                protocol: &definition.protocol,
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema(&schema)
            .data(Data::Stream(reader.clone()))
            .published(true)
            .sign(alice)
            .build()
            .await
            .expect("should create write");

        expected_cids.push(write.cid().unwrap());

        let reply = node.request(write).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for messages without a cursor, and expects to see
    // all 5 records as well as the protocol configuration message.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(alice).build().await.expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let cids = query_reply.entries.expect("should have entries");
    assert_eq!(cids.len(), 6);

    for cid in cids {
        assert!(expected_cids.contains(&cid));
    }

    // --------------------------------------------------
    // Alice writes an additional record.
    // --------------------------------------------------
    let message = WriteBuilder::new()
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema(&schema)
        .data(Data::Stream(reader))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    expected_cids.push(message.cid().unwrap());

    let reply = node.request(message).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for messages beyond the cursor, and
    // expects to see only the additional record.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(alice).build().await.expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 7);

    // --------------------------------------------------
    // Alice reads one of the returned messages.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&entries[0])
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should return a status of Forbidden (403) if the requestor is not the owner
// and has no permission grant.
#[tokio::test]
async fn no_grant() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    let query = QueryBuilder::new().sign(alice).build().await.expect("should create write");
    let Err(Error::Forbidden(e)) = node.request(query).owner(bob.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "author has no grant");
}

// Should return a status of BadRequest (400) if the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new().sign(alice).build().await.expect("should create query");
    query.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}

// Should return a status of BadRequest (400) if an empty filter is provided.
#[tokio::test]
async fn empty_filter() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new().sign(alice).build().await.expect("should create query");
    query.descriptor.filters = vec![MessagesFilter::default()];

    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}

// Should allow querying of messages with matching interface and method grant scope.
#[tokio::test]
async fn match_grant_scope() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesQuery` for Bob.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages { method: Method::Query, protocol: None })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let reply = node.request(bob_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a `free_for_all` protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = node
        .request(configure_any.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a random protocol.
    // --------------------------------------------------
    let configure_rand = ConfigureBuilder::new()
        .definition(Definition::new("http://random.xyz"))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = node
        .request(configure_rand.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a message to the Records `free_for_all` interface.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let schema = definition.types["post"].schema.clone().expect("should have schema");

    let write_any = WriteBuilder::new()
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema(schema)
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write_any.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a random message.
    // --------------------------------------------------
    let data = br#"{"message": "random record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write_rand = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write_rand.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(query).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 5);

    let expected_cids = vec![
        bob_grant.cid().expect("should have cid"),
        configure_any.cid().expect("should have cid"),
        configure_rand.cid().expect("should have cid"),
        write_any.cid().expect("should have cid"),
        write_rand.cid().expect("should have cid"),
    ];
    bob_grant.cid().expect("should have cid");

    for cid in entries {
        assert!(expected_cids.contains(&cid));
    }
}

// Should reject message queries with mismatching method grant scopes.
#[tokio::test]
async fn mismatched_grant_scope() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesSubscribe` for BOB.
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages { method: Method::Subscribe, protocol: None });
    let bob_grant = builder.sign(alice).build().await.expect("should create grant");

    let reply = node.request(bob_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to use the `MessagesSubscribe` grant on a `MessagesQuery` message.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    let Err(Error::Forbidden(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "method is not within grant scope");
}

// Should allow querying of messages with matching protocol grant scope.
#[tokio::test]
async fn match_protocol_scope() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let mut definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    definition.protocol = "http://protocol1".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = node
        .request(configure_any.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    definition.protocol = "http://protocol2".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = node
        .request(configure_any.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesQuery` for BOB.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: Some("http://protocol1".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply = node.request(bob_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .add_filter(MessagesFilter::new().protocol("http://protocol1"))
        .permission_grant_id(&bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(query).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");

    // expect protocol1 Configure message and Bob's grant
    assert_eq!(entries.len(), 2);
}

// Should reject querying with protocol when diallowed by protocol grant scope.
#[tokio::test]
async fn mismatched_protocol_scope() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let mut definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    definition.protocol = "http://protocol1".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = node
        .request(configure_any.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    definition.protocol = "http://protocol2".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = node
        .request(configure_any.clone())
        .owner(alice.did())
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesQuery` for BOB.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: Some("http://protocol1".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let reply = node.request(bob_grant.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protocol2".to_string());
    let query = QueryBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    let Err(Error::Forbidden(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "filter and grant protocols do not match");
}
