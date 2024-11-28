//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::endpoint;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder, RuleSet};
use vercre_dwn::provider::KeyStore;

// Find matching protocols.
#[tokio::test]
async fn find_matches() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures 3 protocols.
    // --------------------------------------------------
    for i in 1..=3 {
        let definition = Definition::new(format!("http://protocol-{i}.xyz"))
            .add_type("foo", ProtocolType::default())
            .add_rule("foo", RuleSet::default());

        let configure = ConfigureBuilder::new()
            .definition(definition)
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
    assert_eq!(body.entries.unwrap().len(), 4);
}
