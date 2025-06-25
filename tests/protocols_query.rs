//! Protocols Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

#![cfg(all(feature = "client", feature = "server"))]

use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Days;
use credibil_dwn::api::Client;
use credibil_dwn::client::grants::{GrantBuilder, RevocationBuilder, Scope};
use credibil_dwn::client::protocols::{
    ConfigureBuilder, Definition, ProtocolType, ProtocolsFilter, QueryBuilder,
};
use credibil_dwn::interfaces::protocols::QueryReply;
use credibil_dwn::{Error, Method, StatusCode, cid};
use credibil_jose::{Jws, Protected, Signature};
use test_utils::{Identity, Provider};
use tokio::sync::OnceCell;
use tokio::time;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static CAROL: OnceCell<Identity> = OnceCell::const_new();
static ALICE_NODE: OnceCell<Client<Provider>> = OnceCell::const_new();
static BOB_NODE: OnceCell<Client<Provider>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("protocols_query_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("protocols_query_bob").await }).await
}
async fn carol() -> &'static Identity {
    CAROL.get_or_init(|| async { Identity::new("protocols_query_carol").await }).await
}
async fn alice_node() -> &'static Client<Provider> {
    let alice = alice().await;
    ALICE_NODE.get_or_init(|| async { Client::new(alice.did(), Provider::new().await) }).await
}
async fn bob_node() -> &'static Client<Provider> {
    let bob = bob().await;
    BOB_NODE.get_or_init(|| async { Client::new(bob.did(), Provider::new().await) }).await
}

// Should return protocols matching the query.
#[tokio::test]
async fn authorized() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures 3 protocols.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")))
            .sign(alice)
            .build()
            .await
            .expect("should build");
        let reply = alice_node.request(configure).execute().await.expect("should configure");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Execute a singular conditional query.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-1.xyz")
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Execute a 'fetch-all' query without filter.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(alice).build().await.expect("should build");
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 3);
}

// Should return published protocols matching the query if query is unauthenticated or unauthorized.
#[tokio::test]
async fn unauthorized() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

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
            .sign(alice)
            .build()
            .await
            .expect("should build");
        let reply = alice_node.request(configure).execute().await.expect("should configure");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Query for a protocol as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query = QueryBuilder::new().filter("http://protocol-2.xyz").build();
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query for a protocol as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 1);

    // --------------------------------------------------
    // Query all published protocols as an anonymous (unauthenticated) user.
    // --------------------------------------------------
    let query = QueryBuilder::new().build();
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Query all published protocols as an unauthorized user.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(bob).build().await.expect("should build");
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 2);
}

// Should fail with a status of BadRequest (400) if protocol is not normalized.
#[tokio::test]
async fn bad_protocol() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter("http://protocol-3.xyz")
        .sign(alice)
        .build()
        .await
        .expect("should build");

    query.descriptor.filter = Some(ProtocolsFilter {
        protocol: "protocol-3.xyz/".to_string(),
    });

    let Err(Error::BadRequest(e)) = alice_node.request(query).execute().await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "invalid URL: protocol-3.xyz/");
}

// Should fail with a status of Unauthorized (401) if signature payload  has
// been tampered with.
#[tokio::test]
async fn tampered_signature() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new().sign(alice).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    let mut payload = authorization.payload().expect("should have payload");
    payload.descriptor_cid = cid::from_value(&"some random value").expect("should have CID");

    let bytes = serde_json::to_vec(&payload).expect("should serialize");
    let base64 = Base64UrlUnpadded::encode_string(&bytes);
    authorization.signature.payload = base64;

    let Err(Error::Unauthorized(_)) = alice_node.request(query).execute().await else {
        panic!("should be Unauthorized");
    };
}

// Should fail with a status of Unauthorized (401) if a bad_request signature is provided.
#[tokio::test]
async fn bad_signature() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new().sign(alice).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = alice_node.request(query).execute().await else {
        panic!("should be Unauthorized");
    };
}

// Should allow an external party to query when they have a valid grant.
#[tokio::test]
async fn valid_grant() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice creates 2 protocols, 1 published and 1 unpublished.
    // --------------------------------------------------
    for i in 1..=2 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")))
            .sign(alice)
            .build()
            .await
            .expect("should build");
        let reply = alice_node.request(configure).execute().await.expect("should configure");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for Alice's protocols.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");
    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    assert_eq!(query_reply.entries.unwrap().len(), 2);

    // --------------------------------------------------
    // Carol attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(bob_grant_id)
        .sign(carol)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant not granted to grantee");

    // --------------------------------------------------
    // Alice revokes Bob's grant.
    // --------------------------------------------------
    let bob_revocation = RevocationBuilder::new()
        .grant(bob_grant)
        .sign(alice)
        .build()
        .await
        .expect("should create revocation");

    let reply = alice_node.request(bob_revocation).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query Alice's protocols but fails.
    // --------------------------------------------------
    let mut query = QueryBuilder::new().sign(alice).build().await.expect("should build");
    let authorization = query.authorization.as_mut().unwrap();

    authorization.signature = Jws {
        payload: "badpayload".to_string(),
        signatures: vec![Signature {
            protected: Protected::default(),
            signature: "badsignature".to_string(),
        }],
    };

    let Err(Error::Unauthorized(_)) = alice_node.request(query).execute().await else {
        panic!("should be Unauthorized");
    };
}

// Should allow scoping the query to a specific protocol.
#[tokio::test]
async fn valid_scope() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates 2 unpublished protocols, 2 unpublished and 1 published.
    // --------------------------------------------------
    for i in 1..=3 {
        let configure = ConfigureBuilder::new()
            .definition(Definition::new(format!("http://protocol-{i}.xyz")).published(i > 2))
            .sign(alice)
            .build()
            .await
            .expect("should build");
        let reply = alice_node.request(configure).execute().await.expect("should configure");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: Some("http://protocol-1.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for protocol he is permitted to access.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-1.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-1.xyz");

    // --------------------------------------------------
    // Bob queries for protocol he is not permitted to access.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-2.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 0);

    // --------------------------------------------------
    // Bob uses his grant to query for the published protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .filter("http://protocol-3.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-3.xyz");

    // --------------------------------------------------
    // Bob uses his grant to query any available protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(query).execute().await.expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].descriptor.definition.protocol, "http://protocol-3.xyz");
}

// Should reject an external party when they present an expired grant.
#[tokio::test]
async fn expired_grant() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .expires_in(1)
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query for Alice's protocols using the expired grant.
    // --------------------------------------------------
    time::sleep(Duration::from_secs(1)).await;

    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant has expired");
}

// Should reject an external party when they present a grant that is not yet active.
#[tokio::test]
async fn inactive_grant() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to query protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Protocols {
            method: Method::Query,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query for Alice's protocols using an inactive grant.
    // --------------------------------------------------
    let mut query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
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

    let Err(Error::Forbidden(e)) = alice_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant is not yet active");
}

// Should reject an external party using a grant with a different scope.
#[tokio::test]
async fn invalid_scope() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "https://example.com/protocol/test".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to query protocols using the `RecordsRead` grant.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should reject an external party using a grant if the grant cannot be found.
#[tokio::test]
async fn missing_grant() {
    let alice_node = alice_node().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Bob attempts to query protocols using a grant that cannot be found in the database.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id("somerandomgrantid")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no grant found");
}

// Should fail if the grant has not been granted for the owner.
#[tokio::test]
async fn incorrect_grantor() {
    let alice_node = alice_node().await;
    let bob_node = bob_node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice gives Carol a permission grant with scope ProtocolsQuery.
    // --------------------------------------------------
    let carol_grant = GrantBuilder::new()
        .granted_to(carol.did())
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "https://example.com/protocol/test".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply = alice_node.request(carol_grant.clone()).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob (for some unknown reason) stores the grant on his web node.
    // --------------------------------------------------
    let mut grant = carol_grant.clone();
    grant.sign_as_owner(bob).await.expect("should sign");

    let reply = bob_node.request(grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Carol attempts (and fails) to use her grant to gain access to Bob's protocols.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .permission_grant_id(carol_grant.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = bob_node.request(query).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant not granted by grantor");
}
