//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::endpoint;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder};
use vercre_dwn::provider::KeyStore;

// Should return protocols matching the query.
#[tokio::test]
async fn query_private() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures 3 protocols.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")))
            .build(&alice_keyring)
            .await
            .expect("should build");
        let reply =
            endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Execute a singular conditional query.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-1.xyz")
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Execute a 'fetch-all' query without filter.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 3);
}

// Should return published protocols matching the query if query is unauthenticated or unauthorized.
#[tokio::test]
async fn query_published() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    // let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures 3 protocols: 1 private + 2 published.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(
                Definition::new(format!("http://protocol-{i}.xyz"))
                    .add_type("foo", ProtocolType::default())
                    .published(i > 1),
            )
            .build(&alice_keyring)
            .await
            .expect("should build");
        let reply =
            endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Query as an anonymous user.
    // --------------------------------------------------
    let query =
        QueryBuilder::new().filter("http://protocol-1.xyz").build_anon().expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query without sufficient permission to access the private configuration.
    // --------------------------------------------------
    let query = QueryBuilder::new().build_anon().expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);
}
