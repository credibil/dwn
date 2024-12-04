//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
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
    let definition = Definition::new("http://minimal.xyz")
        .add_type("foo", ProtocolType::default())
        .add_rule("foo", RuleSet::default());

    let configure = ConfigureBuilder::new()
        .definition(definition)
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

    let definition = Definition::new("http://minimal.xyz")
        .add_type("foo", ProtocolType::default())
        .add_rule("foo", RuleSet::default());

    let mut configure = ConfigureBuilder::new()
        .definition(definition)
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
