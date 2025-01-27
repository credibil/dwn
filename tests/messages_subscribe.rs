//! Messages Subscribe

use core::panic;
use std::time::Duration;

use dwn_node::authorization::Authorization;
use dwn_node::clients::grants::GrantBuilder;
use dwn_node::clients::messages::{QueryBuilder, SubscribeBuilder};
use dwn_node::clients::protocols::ConfigureBuilder;
use dwn_node::clients::records::{Data, ProtocolBuilder, WriteBuilder};
use dwn_node::data::DataStream;
use dwn_node::messages::MessagesFilter;
use dwn_node::permissions::Scope;
use dwn_node::protocols::Definition;
use dwn_node::{Error, Interface, Message, Method, endpoint};
use futures::StreamExt;
use http::StatusCode;
use test_node::key_store::{self, ALICE_DID, BOB_DID};
use test_node::provider::ProviderImpl;
use tokio::time;

// TODO: implement fake provider with no subscription support for this test.
// // Should respond with a status of NotImplemented (501) if subscriptions are
// // not supported.
// #[tokio::test]
// async fn unsupported() {}

// Should respond with a status of BadRequest (400) when message is invalid.
#[tokio::test]
async fn invalid_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    let mut subscribe = SubscribeBuilder::new().build(&alice_signer).await.expect("should build");
    subscribe.descriptor.filters.push(MessagesFilter::default());

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("validation failed for "));
}

// Should allow owner to subscribe their own event stream.
#[tokio::test]
async fn owner_events() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);

    // --------------------------------------------------
    // Alice subscribes to own event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().interface(Interface::Records);
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter)
        .build(&alice_signer)
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
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let message_cid = write.cid().expect("should have cid");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the RecordsWrite event exists.
    // --------------------------------------------------
    let query = QueryBuilder::new().build(&alice_signer).await.expect("should create query");
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
    if let Err(_) = time::timeout(Duration::from_millis(500), find_event).await {
        panic!("should have found event");
    }
}

// Should not allow non-owners to subscribe to unauthorized event streams.
#[tokio::test]
async fn unauthorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // An anonymous use attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let mut subscribe = SubscribeBuilder::new().build(&alice_signer).await.expect("should build");
    subscribe.authorization = Authorization::default();

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("validation failed for "));

    // --------------------------------------------------
    // Bob attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new().build(&bob_signer).await.expect("should build");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing permission grant");
}

// Should allow users to subscribe to events matching grant scope.
#[tokio::test]
async fn interface_scope() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to all her messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: None,
        })
        .build(&alice_signer)
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
        .build(&bob_signer)
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
    let bytes = include_bytes!("protocols/allow-any.json");
    let definition = serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_signer)
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 2. configure a random protocol
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://random.xyz"))
        .build(&alice_signer)
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 3. write a record to the 'allow-any' protocol
    let reader = DataStream::from(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    message_cids.push(write.cid().expect("should have cid"));

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // 4. write a random record
    let reader = DataStream::from(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(&alice_signer)
        .build()
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
    if let Err(_) = time::timeout(Duration::from_millis(500), find_event).await {
        panic!("should have found events");
    }
}

// Should reject subscriptions when interface is not authorized.
#[tokio::test]
async fn unauthorized_interface() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice grants Bob permission to write records scoped to the 'allow-any' protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://allow-any".to_string(),
            limited_to: None,
        })
        .build(&alice_signer)
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
        .build(&bob_signer)
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should reject subscriptions when method is not authorized.
#[tokio::test]
async fn unauthorized_method() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice grants Bob permission to query messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        })
        .build(&alice_signer)
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
        .build(&bob_signer)
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "method is not within grant scope");
}

// Should allow subscribing to protocol filtered messages with matching protocol grant scopes.
#[tokio::test]
async fn protocol_filter() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("protocols/allow-any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_signer)
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
        .build(&alice_signer)
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
        .build(&bob_signer)
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
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://protocol1.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let protocol1_cid = write.cid().expect("should have cid");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    let reader = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://protocol2.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(&alice_signer)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check recevied messages to ensure we received the correct one and
    // nothing we shouldn't have received.
    // --------------------------------------------------
    // check for protocol1 message
    let event_fut = alice_events.next();
    let protocol1 = async move {
        let Some(event) = event_fut.await else {
            panic!("should have found event");
        };
        assert_eq!(protocol1_cid, event.cid().unwrap());
    };
    if let Err(_) = time::timeout(Duration::from_millis(500), protocol1).await {
        panic!("should have found events");
    }

    let remaining = async move {
        if let Some(event) = alice_events.next().await {
            panic!("unexpected event: {:?}", event);
        }
    };
    let _ = time::timeout(Duration::from_millis(500), remaining).await;
}

// Should reject subscribing to messages with incorrect protocol grant scope.
#[tokio::test]
async fn invalid_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_signer = key_store::signer(ALICE_DID);
    let bob_signer = key_store::signer(BOB_DID);

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("protocols/allow-any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_signer)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_signer)
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
        .build(&alice_signer)
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob subscribes to `protocol2` messages in Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .add_filter(MessagesFilter::new().protocol("http://protocol2.xyz"))
        .permission_grant_id(&bob_grant_id)
        .build(&bob_signer)
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "filter and grant protocols do not match");

    // --------------------------------------------------
    // Bob subscribes to `protocol1` or `protocol2` messages in Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .add_filter(MessagesFilter::new().protocol("http://protocol2.xyz"))
        .add_filter(MessagesFilter::new().protocol("http://protocol2.xyz"))
        .permission_grant_id(&bob_grant_id)
        .build(&bob_signer)
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, subscribe, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "filter and grant protocols do not match");
}
