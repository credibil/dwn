//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use tokio::time;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder, RuleSet};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::{Error, endpoint};

// Should allow a protocol definition with no schema or `data_format`.
#[tokio::test]
async fn minimal() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
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
        .definition(
            Definition::new("http://minimal.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
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

// Should overwrite existing protocol if timestamp is newer.
#[tokio::test]
async fn overwrite() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let definition = Definition::new("http://minimal.xyz")
        .add_type("foo", ProtocolType::default())
        .add_rule("foo", RuleSet::default());

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
