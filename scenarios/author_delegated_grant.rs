//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use dwn_node::clients::grants::GrantBuilder;
use dwn_node::clients::protocols::{ConfigureBuilder, QueryBuilder};
use dwn_node::permissions::Scope;
use dwn_node::protocols::Definition;
use dwn_node::{Method, endpoint};
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;

use crate::key_store::{self, ALICE_DID, BOB_DID};
use crate::provider::ProviderImpl;

// Allow author-delegated grant to configure any protocols.
#[tokio::test]
async fn configure_any() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice grants Bob the ability to configure any protocol
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB_DID)
        .request_id("grant_id_1")
        .description("Allow Bob to configure any protocol")
        .delegated(true)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        });

    let bob_grant = builder.build(&alice_signer).await.expect("should create grant");

    // --------------------------------------------------
    // Bob configures the email protocol on Alice's behalf
    // --------------------------------------------------
    let email = include_bytes!("../../protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .delegated_grant(bob_grant.try_into().expect("should convert"))
        .build(&bob_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    assert_snapshot!("configure", reply, {
        ".**.messageTimestamp" => "[messageTimestamp]",
        ".**.signature.payload" => "[payload]",
        ".**.signature.signatures[0].signature" => "[signature]",

        ".*.authorDelegatedGrant.descriptor.dateCreated" => "[dateCreated]",
        ".*.authorDelegatedGrant.descriptor.dataCid" => "[dataCid]",
        ".*.authorDelegatedGrant.recordId" => "[recordId]",
        ".*.authorDelegatedGrant.contextId" => "[contextId]",
        ".*.authorDelegatedGrant.encodedData" => "[encodedData]",
    });

    // --------------------------------------------------
    // Alice fetches the email protocol configured by Bob
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(definition.protocol)
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should find protocol");
    assert_eq!(reply.status.code, StatusCode::OK);

    assert_snapshot!("query", reply, {
        ".**.messageTimestamp" => "[messageTimestamp]",
        ".**.signature.payload" => "[payload]",
        ".**.signature.signatures[0].signature" => "[signature]",

        ".**.authorDelegatedGrant.descriptor.dateCreated" => "[dateCreated]",
        ".**.authorDelegatedGrant.descriptor.dataCid" => "[dataCid]",
        ".**.authorDelegatedGrant.recordId" => "[recordId]",
        ".**.authorDelegatedGrant.contextId" => "[contextId]",
        ".**.authorDelegatedGrant.encodedData" => "[encodedData]",
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
