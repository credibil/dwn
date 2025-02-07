//! Protocols Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use std::sync::LazyLock;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Days;
use credibil_infosec::jose::jws::{Jws, Protected, Signature};
use dwn_node::client::grants::{GrantBuilder, RevocationBuilder, Scope};
use dwn_node::client::protocols::{
    ConfigureBuilder, Definition, ProtocolType, ProtocolsFilter, QueryBuilder,
};
use dwn_node::{Error, Method, StatusCode, cid, endpoint};
use test_node::keystore::{self, Keyring};
use test_node::provider::ProviderImpl;
use tokio::time;

static ALICE: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static BOB: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static CAROL: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());

// Should return protocols matching the query.
#[tokio::test]
async fn authorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice configures 3 protocols.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")))
            .sign(&*ALICE)
            .build()
            .await
            .expect("should build");
        let reply =
            endpoint::handle(&ALICE.did, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Execute a singular conditional query.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-1.xyz")
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Execute a 'fetch-all' query without filter.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should build");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 3);
}

// Should return published protocols matching the query if query is unauthenticated or unauthorized.
#[tokio::test]
async fn unauthorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");

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
            .sign(&*ALICE)
            .build()
            .await
            .expect("should build");
        let reply =
            endpoint::handle(&ALICE.did, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Query for a protocol as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query = QueryBuilder::new().filter("http://protocol-2.xyz").build();
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query for a protocol as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query all published protocols as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query = QueryBuilder::new().build();
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Query all published protocols as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(&*BOB).build().await.expect("should build");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);
}

// Should fail with a status of BadRequest (400) if protocol is not normalized.
#[tokio::test]
async fn bad_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let mut query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    query.descriptor.filter = Some(ProtocolsFilter {
        protocol: "protocol-3.xyz/".to_string(),
    });

    let Err(Error::BadRequest(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "invalid URL: protocol-3.xyz/");
}

// Should fail with a status of Unauthorized (401) if signature payload  has
// been tampered with.
#[tokio::test]
async fn tampered_signature() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let mut query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    let mut payload = authorization.payload().expect("should have payload");
    payload.descriptor_cid = cid::from_value(&"some random value").expect("should have CID");

    let bytes = serde_json::to_vec(&payload).expect("should serialize");
    let base64 = Base64UrlUnpadded::encode_string(&bytes);
    authorization.signature.payload = base64;

    let Err(Error::Unauthorized(_)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should fail with a status of Unauthorized (401) if a bad signature is provided.
#[tokio::test]
async fn bad_signature() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let mut query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should allow an external party to query when they have a valid grant.
#[tokio::test]
async fn valid_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice creates 2 protocols, 1 published and 1 unpublished.
    // --------------------------------------------------
    for i in 1..=2 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")))
            .sign(&*ALICE)
            .build()
            .await
            .expect("should build");
        let reply =
            endpoint::handle(&ALICE.did, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for Alice's protocols.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");
    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert_eq!(body.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Carol attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(bob_grant_id)
        .sign(&*CAROL)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant not granted to grantee");

    // --------------------------------------------------
    // Alice revokes Bob's grant.
    // --------------------------------------------------
    let bob_revocation = RevocationBuilder::new()
        .grant(bob_grant)
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create revocation");

    let reply =
        endpoint::handle(&ALICE.did, bob_revocation, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let mut query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Unauthorized");
    };
}

// Should allow scoping the query to a specific protocol.
#[tokio::test]
async fn valid_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice creates 2 unpublished protocols, 2 unpublished and 1 published.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")).published(i > 2))
            .sign(&*ALICE)
            .build()
            .await
            .expect("should build");
        let reply =
            endpoint::handle(&ALICE.did, configure, &provider).await.expect("should configure");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: Some("http://protocol-1.xyz".to_string()),
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for protocol he is permitted to access.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-1.xyz")
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
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
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
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
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
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
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let reply = endpoint::handle(&ALICE.did, query, &provider).await.expect("should match");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-3.xyz");
}

// Should reject an external party when they present an expired grant.
#[tokio::test]
async fn expired_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .expires_in(1)
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query for Alice's protocols using the expired grant.
    // --------------------------------------------------
    time::sleep(Duration::from_secs(1)).await;

    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant has expired");
}

// Should reject an external party when they present a grant that is not yet active.
#[tokio::test]
async fn inactive_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query for Alice's protocols using an inactive grant.
    // --------------------------------------------------
    let mut query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    // fake inactive grant by setting message's timestamp prior to grant activation
    let older_timestamp = query
        .descriptor
        .base
        .message_timestamp
        .checked_sub_days(Days::new(1))
        .expect("should subtract");
    query.descriptor.base.message_timestamp = older_timestamp;

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant is not yet active");
}

// Should reject an external party using a grant with a different scope.
#[tokio::test]
async fn invalid_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "https://example.com/protocol/test".to_string(),
            limited_to: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&ALICE.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query protocols using the `RecordsRead` grant.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should reject an external party using a grant if the grant cannot be found.
#[tokio::test]
async fn missing_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Bob attempts to query protocols using a grant that cannot be found in the database.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id("somerandomgrantid")
        .sign(&*BOB)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&ALICE.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no grant found");
}

// Should fail if the grant has not been granted for the owner.
#[tokio::test]
async fn incorrect_grantor() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Alice gives Carol a permission grant with scope ProtocolsQuery.
    // --------------------------------------------------
    let carol_grant = GrantBuilder::new()
        .granted_to(&CAROL.did)
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "https://example.com/protocol/test".to_string(),
            limited_to: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(&ALICE.did, carol_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob (for some unknown reason) stores the grant on his web node.
    // --------------------------------------------------
    let mut grant = carol_grant.clone();
    grant.sign_as_owner(&*BOB).await.expect("should sign");

    let reply = endpoint::handle(&BOB.did, grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Carol attempts (and fails) to use her grant to gain access to Bob's protocols.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(carol_grant.record_id)
        .sign(&*CAROL)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&BOB.did, query, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant not granted by grantor");
}
