//! Message Query
//!
//! This test demonstrates how a web node owner create messages and
//! subsequently query for them.

use std::io::Cursor;
use std::sync::LazyLock;

use dwn_node::interfaces::grants::{GrantBuilder, Scope};
use dwn_node::interfaces::messages::{MessagesFilter, QueryBuilder, ReadBuilder};
use dwn_node::interfaces::protocols::{ConfigureBuilder, Definition};
use dwn_node::interfaces::records::{Data, ProtocolBuilder, WriteBuilder};
use dwn_node::{Error, Interface, Message, Method, StatusCode, endpoint};
use test_node::keystore::{self, Keyring};
use test_node::provider::ProviderImpl;

static ALICE: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static BOB: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn owner_messages() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let mut expected_cids = vec![configure.cid().unwrap()];

    let reply = endpoint::handle(&ALICE.did, configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

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
            .sign(&*ALICE)
            .build()
            .await
            .expect("should create write");

        expected_cids.push(write.cid().unwrap());

        let reply = endpoint::handle(&ALICE.did, write, &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for messages without a cursor, and expects to see
    // all 5 records as well as the protocol configuration message.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create query");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should query");
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
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema(&schema)
        .data(Data::Stream(reader))
        .published(true)
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create write");

    expected_cids.push(message.cid().unwrap());

    let reply = endpoint::handle(&ALICE.did, message, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for messages beyond the cursor, and
    // expects to see only the additional record.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create query");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 7);

    // --------------------------------------------------
    // Alice reads one of the returned messages.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .message_cid(&entries[0])
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(&ALICE.did, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
}

// Should return a status of Forbidden (403) if the requestor is not the owner
// and has no permission grant.
#[tokio::test]
async fn no_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(&BOB.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "author has no grant");
}

// Should return a status of BadRequest (400) if the request is invalid.
#[tokio::test]
async fn invalid_request() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let mut query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create query");
    query.descriptor.base.interface = Interface::Protocols;

    let Err(Error::BadRequest(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("validation failed for "));
}

// Should return a status of BadRequest (400) if an empty filter is provided.
#[tokio::test]
async fn empty_filter() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let mut query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create query");
    query.descriptor.filters = vec![MessagesFilter::default()];

    let Err(Error::BadRequest(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("validation failed for "));
}

// Should allow querying of messages with matching interface and method grant scope.
#[tokio::test]
async fn match_grant_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice creates a grant scoped to `EventsQuery` for BOB.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a `free_for_all` protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a random protocol.
    // --------------------------------------------------
    let configure_rand = ConfigureBuilder::new()
        .definition(Definition::new("http://random.xyz"))
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, configure_rand.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

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
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create write");

    let reply =
        endpoint::handle(&ALICE.did, write_any.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a random message.
    // --------------------------------------------------
    let data = br#"{"message": "random record write"}"#;
    let reader = Cursor::new(data.to_vec());

    let write_rand = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create write");

    let reply =
        endpoint::handle(&ALICE.did, write_rand.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------

    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
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

    for entry in entries {
        assert!(expected_cids.contains(&entry));
    }
}

// Should reject message queries with mismatching method grant scopes.
#[tokio::test]
async fn mismatched_grant_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesSubscribe` for BOB.
    // --------------------------------------------------
    let builder = GrantBuilder::new().granted_to(&BOB.did).scope(Scope::Messages {
        method: Method::Subscribe,
        protocol: None,
    });
    let bob_grant = builder.sign(&*ALICE).build().await.expect("should create grant");

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to use the `MessagesSubscribe` grant on a `EventsQuery` message.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "method is not within grant scope");
}

// Should allow querying of messages with matching protocol grant scope.
#[tokio::test]
async fn match_protocol_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let allow_any = include_bytes!("protocols/allow-any.json");
    let mut definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    definition.protocol = "http://protocol1".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    definition.protocol = "http://protocol2".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");
    let reply = endpoint::handle(&ALICE.did, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a grant scoped to `EventsQuery` for BOB.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: Some("http://protocol1".to_string()),
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .add_filter(MessagesFilter::new().protocol("http://protocol1"))
        .permission_grant_id(&bob_grant.record_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
    let entries = query_reply.entries.expect("should have entries");

    // expect protocol1 Configure message and Bob's grant
    assert_eq!(entries.len(), 2);
}

// Should reject querying with protocol when diallowed by protocol grant scope.
#[tokio::test]
async fn mismatched_protocol_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let allow_any = include_bytes!("protocols/allow-any.json");
    let mut definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    definition.protocol = "http://protocol1".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    definition.protocol = "http://protocol2".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a grant scoped to `EventsQuery` for BOB.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: Some("http://protocol1".to_string()),
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protocol2".to_string());
    let query = QueryBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant.record_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "filter and grant protocols do not match");
}
