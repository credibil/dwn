//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_utils::store::ProviderImpl;
use vercre_dwn::handlers::{configure, query};
use vercre_dwn::permissions::{GrantBuilder, ScopeType};
use vercre_dwn::protocols::{ConfigureBuilder, Definition, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::{Interface, Method};

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

// Allow author-delegated grant to configure any protocols.
#[tokio::test]
async fn configure_any() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice grants Bob the ability to configure any protocol
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB_DID)
        .request_id("grant_id_1")
        .description("Allow Bob to configure any protocol")
        .delegated(true)
        .scope(Interface::Protocols, Method::Configure, ScopeType::Protocols { protocol: None });

    let grant_to_bob = builder.build(&alice_keyring).await.expect("should create grant");

    // --------------------------------------------------
    // Bob configures the email protocol on Alice's behalf
    // --------------------------------------------------
    let email = include_bytes!("protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .delegated_grant(grant_to_bob)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = configure::handle(ALICE_DID, configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    assert_snapshot!("configure", reply, {
        ".descriptor.messageTimestamp" => "[messageTimestamp]",
        ".authorization.signature.payload" => "[payload]",
        ".authorization.signature.signatures[0].signature" => "[signature]",
    });

    // --------------------------------------------------
    // Alice fetches the email protocol configured by Bob
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(definition.protocol)
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        query::handle(ALICE_DID, query, provider.clone()).await.expect("should find protocol");
    assert_eq!(reply.status.code, StatusCode::OK);

    assert_snapshot!("query", reply, {
        ".entries[].descriptor.messageTimestamp" => "[messageTimestamp]",
        ".entries[].authorization.signature.payload" => "[payload]",
        ".entries[].authorization.signature.signatures[0].signature" => "[signature]",
    });
}

// Allow author-delegated grant to configure a specific protocol.
#[tokio::test]
async fn configure_one() {}

// Error reply when message invokes a author-delegated grant but no grant is given.
#[tokio::test]
async fn no_grant() {}

// Error when message includes an author-delegated grant but does not reference it in
// author signature.
#[tokio::test]
async fn no_grant_reference() {}
