//! Message Query
//!
//! This test demonstrates how a web node owner create messages and
//! subsequently query for them.

use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::messages::{MessagesFilter, QueryBuilder, ReadBuilder};
use vercre_dwn::permissions::{GrantBuilder, ScopeProtocol};
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData, WriteProtocol};
use vercre_dwn::{Error, Interface, Message, Method, endpoint};

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn owner_messages() {
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
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let schema = definition.types["post"].schema.clone().expect("should have schema");
    let protocol = WriteProtocol {
        protocol: definition.protocol.clone(),
        protocol_path: "post".to_string(),
    };

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
#[tokio::test]
async fn empty_filter() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    query.descriptor.filters = vec![MessagesFilter::default()];

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be a bad request");
    };
}

// **************************************************
// Grant Scopes
// **************************************************

// Should allow querying of messages with matching interface and method grant scope.
#[tokio::test]
async fn match_grant_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesQuery` for Bob.
    // --------------------------------------------------
    let builder =
        GrantBuilder::new().granted_to(BOB_DID).scope(Interface::Messages, Method::Query, None);
    let bob_grant = builder.build(&alice_keyring).await.expect("should create grant");

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a `free_for_all` protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a random protocol.
    // --------------------------------------------------
    let configure_rand = ConfigureBuilder::new()
        .definition(
            Definition::new("http://random.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_rand.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a message to the Records `free_for_all` interface.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let protocol = WriteProtocol {
        protocol: definition.protocol.clone(),
        protocol_path: "post".to_string(),
    };
    let schema = definition.types["post"].schema.clone().expect("should have schema");

    let write_any = WriteBuilder::new()
        .protocol(protocol.clone())
        .schema(schema)
        .data(WriteData::Reader(reader))
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply =
        endpoint::handle(ALICE_DID, write_any.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a random message.
    // --------------------------------------------------
    let data = br#"{"message": "random record write"}"#;
    let reader = DataStream::from(data.to_vec());

    let write_rand = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply =
        endpoint::handle(ALICE_DID, write_rand.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
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
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesSubscribe` for Bob.
    // --------------------------------------------------
    let builder =
        GrantBuilder::new().granted_to(BOB_DID).scope(Interface::Messages, Method::Subscribe, None);
    let bob_grant = builder.build(&alice_keyring).await.expect("should create grant");

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to use the `MessagesSubscribe` grant on a `MessagesQuery` message.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should not be authorized");
    };
}

// **************************************************
// Protocol Grant Scopes
// **************************************************

// Should allow querying of messages with matching protocol grant scope.
#[tokio::test]
async fn match_protocol_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let mut definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    definition.protocol = "http://protcol1".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    definition.protocol = "http://protcol2".to_string();

    let configure_any = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, configure_any.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a grant scoped to `MessagesQuery` for Bob.
    // --------------------------------------------------
    let builder = GrantBuilder::new().granted_to(BOB_DID).scope(
        Interface::Messages,
        Method::Query,
        Some(ScopeProtocol::Simple {
            protocol: "http://protcol1".to_string(),
        }),
    );
    let bob_grant = builder.build(&alice_keyring).await.expect("should create grant");

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to query for the messages.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protcol1".to_string());
    let query = QueryBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should be records read");
    println!("{:?}", query_reply);

    // let entries = query_reply.entries.expect("should have entries");
    // assert_eq!(entries.len(), 2);
}
