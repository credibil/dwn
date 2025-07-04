//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use std::sync::LazyLock;

use credibil_dwn::client::grants::{GrantBuilder, Scope};
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition, QueryBuilder};
use credibil_dwn::{Method, endpoint};
use http::StatusCode;
use test_node::Provider;
use test_node::kms::{self, Keyring};

static ALICE: LazyLock<Keyring> = LazyLock::new(Keyring::new);
static BOB: LazyLock<Keyring> = LazyLock::new(Keyring::new);

// Allow author-delegated grant to configure any protocols.
#[tokio::test]
async fn configure_any() {
    let node = node().await;

    // --------------------------------------------------
    // Alice grants Bob the ability to configure any protocol
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB.did(),)
        .request_id("grant_id_1")
        .description("Allow Bob to configure any protocol")
        .delegated(true)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        });

    let bob_grant = builder.sign(&*ALICE).build().await.expect("should create grant");

    // --------------------------------------------------
    // Bob configures the email protocol on Alice's behalf
    // --------------------------------------------------
    let email = include_bytes!("../../../tests/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .delegated_grant(bob_grant.try_into().expect("should convert"))
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE.did(),, configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the email protocol configured by Bob
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(&definition.protocol)
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE.did(),, query, &provider).await.expect("should find protocol");
    assert_eq!(reply.status, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = &body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, definition.protocol);
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
