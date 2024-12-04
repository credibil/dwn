//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use tokio::time;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::{Error, Message, endpoint};

// Should allow a protocol definition with no schema or `data_format`.
#[tokio::test]
async fn minimal() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// TODO: add support for multiple signatures to infosec
// // Should return a status of BadRequest (400) whe more than 1 signature is set.
// #[tokio::test]
// async fn two_signatures() {}

// Should return a status of Forbidden (403) when authorization fails.
#[tokio::test]
async fn forbidden() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // configure a protocol
    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .build(&alice_keyring)
        .await
        .expect("should build");

    // set a bad signature
    configure.authorization.signature.signatures[0].signature = "bad".to_string();

    let Err(Error::Unauthorized(_)) = endpoint::handle(ALICE_DID, configure, &provider).await
    else {
        panic!("should not configure protocol");
    };
}

// Should overwrite existing protocol when timestamp is newer.
#[tokio::test]
async fn overwrite_older() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let definition = Definition::new("http://minimal.xyz");

    // --------------------------------------------------
    // Alice creates an older protocol but doesn't use it.
    // --------------------------------------------------
    let older = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    time::sleep(time::Duration::from_secs(1)).await;

    // --------------------------------------------------
    // Alice configures a newer protocol.
    // --------------------------------------------------
    let newer = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, newer, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to configure the older protocol and fails.
    // --------------------------------------------------
    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, older, &provider).await else {
        panic!("should not configure protocol");
    };

    // --------------------------------------------------
    // Alice updates the existing protocol.
    // --------------------------------------------------
    let update = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, update, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Control: only the most recent protocol should exist.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://minimal.xyz")
        .build(&alice_keyring)
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should exist");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should overwrite existing protocol with an identical timestamp when new
// protocol is lexicographically larger.
#[tokio::test]
async fn overwrite_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let definition_1 = Definition::new("http://minimal.xyz").add_type("foo1", ProtocolType {
        schema: None,
        data_formats: Some(vec!["bar1".to_string()]),
    });
    let definition_2 = Definition::new("http://minimal.xyz").add_type("foo2", ProtocolType {
        schema: None,
        data_formats: Some(vec!["bar2".to_string()]),
    });
    let definition_3 = Definition::new("http://minimal.xyz").add_type("foo3", ProtocolType {
        schema: None,
        data_formats: Some(vec!["bar3".to_string()]),
    });

    // --------------------------------------------------
    // Alice creates 3 messages sorted in by CID.
    // --------------------------------------------------
    let mut messages = vec![
        ConfigureBuilder::new()
            .definition(definition_1)
            .build(&alice_keyring)
            .await
            .expect("should build"),
        ConfigureBuilder::new()
            .definition(definition_2)
            .build(&alice_keyring)
            .await
            .expect("should build"),
        ConfigureBuilder::new()
            .definition(definition_3)
            .build(&alice_keyring)
            .await
            .expect("should build"),
    ];

    let timestamp = messages[0].descriptor().message_timestamp;
    messages[1].descriptor.base.message_timestamp = timestamp;
    messages[2].descriptor.base.message_timestamp = timestamp;

    messages.sort_by(|a, b| a.cid().unwrap().cmp(&b.cid().unwrap()));

    // --------------------------------------------------
    // Alice configures the middle protocol.
    // --------------------------------------------------
    // configure protocol
    let reply = endpoint::handle(ALICE_DID, messages[1].clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // check the protocol with the smallest CID cannot be written
    let Err(Error::Conflict(_)) = endpoint::handle(ALICE_DID, messages[0].clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };

    // check the protocol with the largest CID can be written
    let reply = endpoint::handle(ALICE_DID, messages[2].clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Control: only the most recent protocol should exist.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://minimal.xyz")
        .build(&alice_keyring)
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should exist");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}
