//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use base64ct::{Base64UrlUnpadded, Encoding};
use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::cid;
use vercre_dwn::permissions::{GrantBuilder, RevocationBuilder, Scope};
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::store::ProtocolsFilter;
use vercre_dwn::{Error, Method, endpoint};
use vercre_infosec::jose::jws::{Jws, Protected, Signature};

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
    // Alice configures 3 protocols: 1 unpublished + 2 published.
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

// Should fail with a status of Unauthorized (401) if signature payload  has
// been tampered with.
#[tokio::test]
async fn tampered_signature() {
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
        panic!("should be Unauthorized");
    };
}

// Should fail with a status of Unauthorized (401) if a bad signature is provided.
#[tokio::test]
async fn bad_signature() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should allow an external party to query when they have a valid grant.
#[tokio::test]
async fn valid_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 2 protocols, 1 published and 1 unpublished.
    // --------------------------------------------------
    for i in 1..=2 {
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
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for Alice's protocols.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Carol attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(bob_grant_id)
        .build(&carol_keyring)
        .await
        .expect("should build");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be Forbidden");
    };

    // --------------------------------------------------
    // Alice revokes Bob's grant.
    // --------------------------------------------------
    let bob_revocation = RevocationBuilder::new()
        .grant(bob_grant)
        .build(&alice_keyring)
        .await
        .expect("should create revocation");

    let reply = endpoint::handle(ALICE_DID, bob_revocation, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let mut query = QueryBuilder::new().build(&alice_keyring).await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should allow scoping the query to a specific protocol.
#[tokio::test]
async fn valid_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 2 unpublished protocols, 2 unpublished and 1 published.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")).published(i > 2))
            .build(&alice_keyring)
            .await
            .expect("should build");
        let reply =
            endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: Some("http://protocol-1.xyz".to_string()),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for protocol he is permitted to access.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-1.xyz")
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-1.xyz");

    // --------------------------------------------------
    // Bob queries for protocol he is not permitted to access.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-2.xyz")
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 0);

    // --------------------------------------------------
    // Bob uses his grant to query for the published protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-3.xyz")
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-3.xyz");

    // --------------------------------------------------
    // Bob uses his grant to query any available protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-3.xyz");
}
