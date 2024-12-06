//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use base64ct::{Base64UrlUnpadded, Encoding};
use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::cid;
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::store::ProtocolsFilter;
use vercre_dwn::{Error, endpoint};

// Should return protocols matching the query.
#[tokio::test]
async fn authorized() {
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
async fn unauthorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

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
    // Query for a protocol as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query =
        QueryBuilder::new().filter("http://protocol-2.xyz").anonymous().expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query for a protocol as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .build(&bob_keyring)
        .await
        .expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query all published protocols as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query = QueryBuilder::new().anonymous().expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Query all published protocols as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&bob_keyring).await.expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);
}

// Should fail with a status of BadRequest (400) if protocol is not normalized.
#[tokio::test]
async fn bad_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .build(&alice_keyring)
        .await
        .expect("should build");

    query.descriptor.filter = Some(ProtocolsFilter {
        protocol: "protocol-3.xyz/".to_string(),
    });

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be BadRequest");
    };
}

// Should fail with a status of BadRequest (400) if signature payload references a
// different message descriptor.
#[tokio::test]
async fn incorrect_descriptor() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    let mut payload = authorization.jws_payload().expect("should have payload");
    payload.descriptor_cid = cid::from_value(&"some random value").expect("should have CID");

    let bytes = serde_json::to_vec(&payload).expect("should serialize");
    let base64 = Base64UrlUnpadded::encode_string(&bytes);
    authorization.signature.payload = base64;

    let Err(Error::Unauthorized(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be BadRequest");
    };
}
