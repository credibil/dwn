//! Message Query
//!
//! This test demonstrates how a web node owner create differnt types of
//! messages and subsequently query for them.

use std::collections::BTreeMap;

use dwn_node::interfaces::grants::{GrantBuilder, RevocationBuilder, Scope};
use dwn_node::interfaces::protocols::{
    Action, ActionRule, Actor, ConfigureBuilder, Definition, ProtocolType, QueryBuilder, RuleSet,
};
use dwn_node::provider::MessageStore;
use dwn_node::store::ProtocolsQueryBuilder;
use dwn_node::{Error, Message, Method, StatusCode, endpoint};
use test_node::key_store;
use test_node::provider::ProviderImpl;
use tokio::time;

// Should allow a protocol definition with no schema or `data_format`.
#[tokio::test]
async fn minimal() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// LATER: add support for multiple signatures to infosec
// // Should return a status of BadRequest (400) whe more than 1 signature is set.
// #[tokio::test]
// async fn two_signatures() {}

// Should return a status of Forbidden (403) when authorization fails.
#[tokio::test]
async fn forbidden() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    // configure a protocol
    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // set a bad signature
    configure.authorization.signature.signatures[0].signature = "bad".to_string();

    let Err(Error::Unauthorized(_)) = endpoint::handle(&alice.did, configure, &provider).await
    else {
        panic!("should be Unauthorized");
    };
}

// Should overwrite existing protocol when timestamp is newer.
#[tokio::test]
async fn overwrite_older() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let definition = Definition::new("http://minimal.xyz");

    // --------------------------------------------------
    // Alice creates an older protocol but doesn't use it.
    // --------------------------------------------------
    let older = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    time::sleep(time::Duration::from_secs(1)).await;

    // --------------------------------------------------
    // Alice configures a newer protocol.
    // --------------------------------------------------
    let newer = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, newer, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to configure the older protocol and fails.
    // --------------------------------------------------
    let Err(Error::Conflict(e)) = endpoint::handle(&alice.did, older, &provider).await else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "message is not the latest");

    // --------------------------------------------------
    // Alice updates the existing protocol.
    // --------------------------------------------------
    let update = ConfigureBuilder::new()
        .definition(definition)
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, update, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Control: only the most recent protocol should exist.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://minimal.xyz")
        .sign(&alice)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(&alice.did, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should exist");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should overwrite existing protocol with an identical timestamp when new
// protocol is lexicographically larger.
#[tokio::test]
async fn overwrite_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let definition_1 = Definition::new("http://minimal.xyz").add_type(
        "foo1",
        ProtocolType {
            schema: None,
            data_formats: Some(vec!["bar1".to_string()]),
        },
    );
    let definition_2 = Definition::new("http://minimal.xyz").add_type(
        "foo2",
        ProtocolType {
            schema: None,
            data_formats: Some(vec!["bar2".to_string()]),
        },
    );
    let definition_3 = Definition::new("http://minimal.xyz").add_type(
        "foo3",
        ProtocolType {
            schema: None,
            data_formats: Some(vec!["bar3".to_string()]),
        },
    );

    // --------------------------------------------------
    // Alice creates 3 messages sorted in by CID.
    // --------------------------------------------------
    let mut messages = vec![
        ConfigureBuilder::new()
            .definition(definition_1)
            .sign(&alice)
            .build()
            .await
            .expect("should build"),
        ConfigureBuilder::new()
            .definition(definition_2)
            .sign(&alice)
            .build()
            .await
            .expect("should build"),
        ConfigureBuilder::new()
            .definition(definition_3)
            .sign(&alice)
            .build()
            .await
            .expect("should build"),
    ];

    // change timestamp before sorting (CID is recalculated)
    let timestamp = messages[0].descriptor().message_timestamp;
    messages[1].descriptor.base.message_timestamp = timestamp;
    messages[2].descriptor.base.message_timestamp = timestamp;

    messages.sort_by(|a, b| a.cid().unwrap().cmp(&b.cid().unwrap()));

    // --------------------------------------------------
    // Alice attempts to configure all 3 protocols, failing when the protocol
    // CID is smaller than the existing entry.
    // --------------------------------------------------
    // configure protocol
    let reply = endpoint::handle(&alice.did, messages[1].clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // check the protocol with the smallest CID cannot be written
    let Err(Error::Conflict(e)) = endpoint::handle(&alice.did, messages[0].clone(), &provider).await
    else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "message CID is smaller than existing entry");

    // check the protocol with the largest CID can be written
    let reply = endpoint::handle(&alice.did, messages[2].clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Control: only the most recent protocol should exist.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://minimal.xyz")
        .sign(&alice)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(&alice.did, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should exist");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should return a status of BadRequest (400) when protocol is not normalized.
#[tokio::test]
async fn invalid_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("bad-protocol.xyz/"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // override builder's normalizing of  protocol
    configure.descriptor.definition.protocol = "minimal.xyz/".to_string();

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "invalid URL: minimal.xyz/");
}

// Should return a status of BadRequest (400) when schema is not normalized.
#[tokio::test]
async fn invalid_schema() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz").add_type(
            "foo",
            ProtocolType {
                schema: Some("bad-schema.xyz/".to_string()),
                data_formats: None,
            },
        ))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // override builder's normalizing of  protocol
    configure.descriptor.definition.types.insert(
        "foo".to_string(),
        ProtocolType {
            schema: Some("bad-schema.xyz/".to_string()),
            data_formats: None,
        },
    );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "invalid URL: bad-schema.xyz/");
}

// Should reject non-owner requests with no grant with status of Forbidden (403).
#[tokio::test]
async fn no_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();
    let bob = key_store::new_keyring();

    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(&bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "author has no grant");
}

// Should reject request when action rule contains duplicated actors (`who`
// or `who` + `of` combination).
#[tokio::test]
async fn duplicate_actor() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    // --------------------------------------------------
    // Duplicate 'who' with 'can'.
    // --------------------------------------------------
    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // overwrite builder (it validates definition)
    configure.descriptor.definition =
        Definition::new("http://foo.xyz").add_type("foo", ProtocolType::default()).add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![
                    ActionRule {
                        who: Some(Actor::Anyone),
                        can: vec![Action::Create],
                        ..ActionRule::default()
                    },
                    ActionRule {
                        who: Some(Actor::Anyone),
                        can: vec![Action::Update],
                        ..ActionRule::default()
                    },
                ]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "an actor may only have one rule within a rule set");

    // --------------------------------------------------
    // Duplicate 'who' with 'of' in a nested rule set.
    // --------------------------------------------------
    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // overwrite builder (it validates definition)
    configure.descriptor.definition = Definition::new("http://user-foo.xyz")
        .add_type("foo", ProtocolType::default())
        .add_type("bar", ProtocolType::default())
        .add_rule(
            "user",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![
                    ActionRule {
                        who: Some(Actor::Recipient),
                        of: Some("foo".to_string()),
                        can: vec![Action::Create],
                        ..ActionRule::default()
                    },
                    ActionRule {
                        who: Some(Actor::Recipient),
                        of: Some("foo".to_string()),
                        can: vec![Action::Update],
                        ..ActionRule::default()
                    },
                ]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "an actor may only have one rule within a rule set");
}

// Should reject request when action rule contains duplicated roles.
#[tokio::test]
async fn duplicate_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://foo.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // overwrite builder (it validates definition)
    configure.descriptor.definition = Definition::new("http://foo.xyz")
        .add_type("user", ProtocolType::default())
        .add_type("foo", ProtocolType::default())
        .add_rule(
            "user",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                structure: BTreeMap::from([(
                    "foo".to_string(),
                    RuleSet {
                        actions: Some(vec![
                            ActionRule {
                                who: Some(Actor::Anyone),
                                of: Some("foo".to_string()),
                                ..ActionRule::default()
                            },
                            ActionRule {
                                who: Some(Actor::Anyone),
                                of: Some("foo".to_string()),
                                ..ActionRule::default()
                            },
                        ]),
                        ..RuleSet::default()
                    },
                )]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should not configure protocol");
    };
    assert!(e.starts_with("validation failed for"));
}

// Should reject request when role action rule does not contain all read actions
// (Action::Read, Action::Query, Action::Subscribe).
#[tokio::test]
async fn invalid_read_action() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let mut configure = ConfigureBuilder::new()
        .definition(Definition::new("http://foo.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    // --------------------------------------------------
    // Missing Action::Subscribe.
    // --------------------------------------------------
    configure.descriptor.definition = Definition::new("http://foo.xyz")
        .add_type("friend", ProtocolType::default())
        .add_type("foo", ProtocolType::default())
        .add_rule(
            "friend",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![ActionRule {
                    role: Some("friend".to_string()),
                    can: vec![Action::Read, Action::Query],
                    ..ActionRule::default()
                }]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure.clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "role friend is missing read-like actions");

    // --------------------------------------------------
    // Missing Action::Query.
    // --------------------------------------------------
    configure.descriptor.definition = Definition::new("http://foo.xyz")
        .add_type("friend", ProtocolType::default())
        .add_type("foo", ProtocolType::default())
        .add_rule(
            "friend",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![ActionRule {
                    role: Some("friend".to_string()),
                    can: vec![Action::Read, Action::Subscribe],
                    ..ActionRule::default()
                }]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure.clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "role friend is missing read-like actions");

    // --------------------------------------------------
    // Missing Action::Read.
    // --------------------------------------------------
    configure.descriptor.definition = Definition::new("http://foo.xyz")
        .add_type("friend", ProtocolType::default())
        .add_type("foo", ProtocolType::default())
        .add_rule(
            "friend",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![ActionRule {
                    role: Some("friend".to_string()),
                    can: vec![Action::Query, Action::Subscribe],
                    ..ActionRule::default()
                }]),
                ..RuleSet::default()
            },
        );

    let Err(Error::BadRequest(e)) = endpoint::handle(&alice.did, configure.clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "role friend is missing read-like actions");

    // --------------------------------------------------
    // Control: it should suceed when all actions are present.
    // --------------------------------------------------
    configure.descriptor.definition = Definition::new("http://foo.xyz")
        .add_type("friend", ProtocolType::default())
        .add_type("foo", ProtocolType::default())
        .add_rule(
            "friend",
            RuleSet {
                role: Some(true),
                ..RuleSet::default()
            },
        )
        .add_rule(
            "foo",
            RuleSet {
                actions: Some(vec![ActionRule {
                    role: Some("friend".to_string()),
                    can: vec![Action::Read, Action::Query, Action::Subscribe],
                    ..ActionRule::default()
                }]),
                ..RuleSet::default()
            },
        );

    let reply =
        endpoint::handle(&alice.did, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow an external party to configure a protocol when they have a valid grant.
#[tokio::test]
async fn valid_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();
    let bob = key_store::new_keyring();
    let carol = key_store::new_keyring();

    // --------------------------------------------------
    // Alice grants Bob permission to configure protocols.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did)
        .scope(Scope::Protocols {
            method: Method::Configure,
            protocol: None,
        })
        .sign(&alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&alice.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob configures a protocol on Alice's web node.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .permission_grant_id(&bob_grant_id)
        .sign(&bob)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol should not be able to use Bob's grant to configure a protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .permission_grant_id(&bob_grant_id)
        .sign(&carol)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&alice.did, configure.clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "grant not granted to grantee");

    // --------------------------------------------------
    // Alice revokes Bob's grant.
    // --------------------------------------------------
    let bob_revocation = RevocationBuilder::new()
        .grant(bob_grant)
        .sign(&alice)
        .build()
        .await
        .expect("should create revocation");

    let reply = endpoint::handle(&alice.did, bob_revocation, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify Bob can no longer use the grant.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://minimal.xyz"))
        .permission_grant_id(bob_grant_id)
        .sign(&carol)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&alice.did, configure, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant not granted to grantee");
}

// Should allow configuring a specific protocol.
#[tokio::test]
async fn configure_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();
    let bob = key_store::new_keyring();

    // --------------------------------------------------
    // Alice grants Bob permission to configure protoocols for a specific protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did)
        .scope(Scope::Protocols {
            method: Method::Configure,
            protocol: Some("https://example.com/protocol/allowed".to_string()),
        })
        .sign(&alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply =
        endpoint::handle(&alice.did, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob configures a protocol for the permitted protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("https://example.com/protocol/allowed"))
        .permission_grant_id(&bob_grant_id)
        .sign(&bob)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Bob fails to configure a protocol for a different protocol.
    // --------------------------------------------------
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("https://example.com/protocol/not-allowed"))
        .permission_grant_id(bob_grant_id)
        .sign(&bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(&alice.did, configure.clone(), &provider).await
    else {
        panic!("should not configure protocol");
    };
    assert_eq!(e, "message and grant protocols do not match");
}

// Should add an event when a protocol is configured.
#[tokio::test]
async fn configure_event() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let configure = ConfigureBuilder::new()
        .definition(Definition::new("https://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // check log
    let query = ProtocolsQueryBuilder::new().protocol("https://minimal.xyz").build();
    let (entries, _) =
        MessageStore::query(&provider, &alice.did, &query).await.expect("should query");
    assert_eq!(entries.len(), 1);
}

// Should delete older events when one is overwritten.
#[tokio::test]
async fn delete_older_events() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    let oldest = ConfigureBuilder::new()
        .definition(Definition::new("https://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let reply =
        endpoint::handle(&alice.did, oldest, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    time::sleep(time::Duration::from_secs(1)).await;

    let newest = ConfigureBuilder::new()
        .definition(Definition::new("https://minimal.xyz"))
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let newest_cid = newest.cid().expect("should have CID");

    let reply =
        endpoint::handle(&alice.did, newest, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // check log

    let query = ProtocolsQueryBuilder::new().protocol("https://minimal.xyz").build();
    let (entries, _) =
        MessageStore::query(&provider, &alice.did, &query).await.expect("should query");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cid().unwrap(), newest_cid);
}
