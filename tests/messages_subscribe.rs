//! Messages Subscribe

use core::panic;
use std::time::Duration;

use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use futures::StreamExt;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::messages::{MessagesFilter, QueryBuilder, SubscribeBuilder};
use vercre_dwn::permissions::{GrantBuilder, Scope};
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData};
use vercre_dwn::{Authorization, Error, Interface, Message, Method, endpoint};

// TODO: implement fake provider with no subscription support for this test.
// // Should respond with a status of NotImplemented (501) if subscriptions are
// // not supported.
// #[tokio::test]
// async fn unsupported() {}

// Should respond with a status of BadRequest (400) when message is invalid.
#[tokio::test]
async fn invalid_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut subscribe = SubscribeBuilder::new().build(&alice_keyring).await.expect("should build");
    subscribe.descriptor.filters.push(MessagesFilter::default());

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should have failed");
    };
}

// Should allow owner to subscribe their own event stream.
#[tokio::test]
async fn owner_events() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice subscribes to own event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().interface(Interface::Records);
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter)
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply = endpoint::handle(ALICE_DID, subscribe, &provider).await.expect("should subscribe");
    assert_eq!(reply.status.code, StatusCode::OK);
    let mut event_stream = reply.body.expect("should have body").subscription;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let reader = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let message_cid = write.cid().expect("should have cid");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the RecordsWrite event exists.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    let Some(entry_cid) = entries.first() else {
        panic!("should have entry");
    };
    assert_eq!(entry_cid, &message_cid);

    // --------------------------------------------------
    // The subscriber should have a matching write event.
    // --------------------------------------------------
    let find_event = async move {
        while let Some(event) = event_stream.next().await {
            if message_cid == event.cid().unwrap() {
                break;
            }
        }
    };
    if let Err(_) = tokio::time::timeout(Duration::from_millis(500), find_event).await {
        panic!("should have found event");
    }
}

// Should not allow non-owners to subscribe to unauthorized event streams.
#[tokio::test]
async fn unauthorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // An anonymous use attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let mut subscribe = SubscribeBuilder::new().build(&alice_keyring).await.expect("should build");
    subscribe.authorization = Authorization::default();

    let Err(Error::BadRequest(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should have failed");
    };

    // --------------------------------------------------
    // Bob attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new().build(&bob_keyring).await.expect("should build");
    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should have failed");
    };
}

// Should allow users to subscribe to events matching grant scope.
#[tokio::test]
async fn interface_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to all her messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to subscribe to Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, subscribe, &provider).await.expect("should subscribe");
    assert_eq!(reply.status.code, StatusCode::OK);
    let mut alice_events = reply.body.expect("should have body").subscription;

    // --------------------------------------------------
    // Alice writes a number of messages.
    // --------------------------------------------------
    let mut message_cids = vec![];

    // 1. configure 'allow-any' protocol
    let bytes = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let definition = serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 2. configure a random protocol
    let configure = ConfigureBuilder::new()
        .definition(
            Definition::new("http://random.xyz")
                .add_type("foo", ProtocolType::default())
                .add_rule("foo", RuleSet::default()),
        )
        .build(&alice_keyring)
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 3. write a record to the 'allow-any' protocol
    let reader = DataStream::from(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .protocol(vercre_dwn::records::WriteProtocol {
            protocol: definition.protocol.clone(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .build(&alice_keyring)
        .await
        .expect("should create write");

    message_cids.push(write.cid().expect("should have cid"));

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 4. write a random record
    let reader = DataStream::from(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .build(&alice_keyring)
        .await
        .expect("should create write");

    message_cids.push(write.cid().expect("should have cid"));

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob's event stream should have matching events.
    // --------------------------------------------------
    let find_event = async move {
        let mut event_count = 0;
        while let Some(event) = alice_events.next().await {
            if message_cids.contains(&event.cid().unwrap()) {
                event_count += 1;
            }
            if event_count >= 4 {
                break;
            }
        }
    };
    if let Err(_) = tokio::time::timeout(Duration::from_millis(500), find_event).await {
        panic!("should have found events");
    }
}

// Should reject subscriptions when interface is not authorized.
#[tokio::test]
async fn unauthorized_interface() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice grants Bob permission to write records scoped to the 'allow-any' protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://allow-any".to_string(),
            options: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to subscribe to messages (and fails).
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be forbidden");
    };
}

// Should reject subscriptions when method is not authorized.
#[tokio::test]
async fn unauthorized_method() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice grants Bob permission to query messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to subscribe to messages (and fails).
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be forbidden");
    };
}

// Should allow subscribing to protocol filtered messages with matching protocol grant scopes.
#[tokio::test]
async fn protocol_filter() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to `protocol1` messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: Some("http://protocol1.xyz".to_string()),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob subscribes to `protocol1` messages in Alice's event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protocol1.xyz");
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let reply = endpoint::handle(ALICE_DID, subscribe, &provider).await.expect("should subscribe");
    assert_eq!(reply.status.code, StatusCode::OK);
    let mut alice_events = reply.body.expect("should have body").subscription;

    // --------------------------------------------------
    // Alice writes 2 records, the first to `protocol1` and the second to `protocol2`.
    // --------------------------------------------------
    // protocol1
    let reader = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .protocol(vercre_dwn::records::WriteProtocol {
            protocol: "http://protocol1.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let protocol1_cid = write.cid().expect("should have cid");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    let reader = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(WriteData::Reader(reader))
        .protocol(vercre_dwn::records::WriteProtocol {
            protocol: "http://protocol2.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check recevied messages to ensure we received the correct one and
    // nothing we shouldn't have received.
    // --------------------------------------------------
    // check for protocol1 message
    let find_event = async move {
        while let Some(event) = alice_events.next().await {
            if protocol1_cid == event.cid().unwrap() {
                break;
            }
            panic!("unexpected event: {:?}", event);
        }
    };
    if let Err(_) = tokio::time::timeout(Duration::from_millis(200), find_event).await {
        panic!("should have found events");
    }
}

// Should reject subscribing to messages with incorrect protocol grant scope.
#[tokio::test]
async fn invalid_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to `protocol1` messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: Some("http://protocol1.xyz".to_string()),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob subscribes to `protocol2` messages in Alice's event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protocol2.xyz");
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be forbidden");
    };

    // --------------------------------------------------
    // Bob subscribes to `protocol1` or `protocol2` messages in Alice's event stream.
    // --------------------------------------------------
    let filter1 = MessagesFilter::new().protocol("http://protocol2.xyz");
    let filter2 = MessagesFilter::new().protocol("http://protocol2.xyz");
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter1)
        .add_filter(filter2)
        .permission_grant_id(&bob_grant_id)
        .build(&bob_keyring)
        .await
        .expect("should build");

    let Err(Error::Forbidden(_)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be forbidden");
    };
}
