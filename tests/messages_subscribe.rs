//! Messages Subscribe

#![cfg(all(feature = "client", feature = "server"))]

use core::panic;
use std::io::Cursor;
use std::time::Duration;

use credibil_dwn::api::Client;
use credibil_dwn::authorization::Authorization;
use credibil_dwn::client::grants::{GrantBuilder, Scope};
use credibil_dwn::client::messages::{MessagesFilter, QueryBuilder, SubscribeBuilder};
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{Data, ProtocolBuilder, WriteBuilder};
use credibil_dwn::interfaces::messages::{QueryReply, SubscribeReply};
use credibil_dwn::{Error, Interface, Method, StatusCode};
use futures::StreamExt;
use test_utils::{Identity, Provider};
use tokio::sync::OnceCell;
use tokio::time;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static ALICE_NODE: OnceCell<Client<Provider>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("messages_subscribe_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("messages_subscribe_bob").await }).await
}
async fn alice_node() -> &'static Client<Provider> {
    let alice = alice().await;
    ALICE_NODE.get_or_init(|| async { Client::new(alice.did(), Provider::new().await) }).await
}

// TODO: implement fake provider with no subscription support for this test.
// // Should respond with a status of NotImplemented (501) if subscriptions are
// // not supported.
// #[tokio::test]
// async fn unsupported() {}

// Should respond with a status of BadRequest (400) when message is invalid.
#[tokio::test]
async fn invalid_message() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    let mut subscribe = SubscribeBuilder::new().sign(alice).build().await.expect("should build");
    subscribe.descriptor.filters.push(MessagesFilter::default());

    let Err(Error::BadRequest(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}

// Should allow owner to subscribe their own event stream.
#[tokio::test]
async fn owner_events() {
    let alice_node = alice_node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice subscribes to own event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().interface(Interface::Records);
    let subscribe =
        SubscribeBuilder::new().add_filter(filter).sign(alice).build().await.expect("should build");
    let reply = alice_node.request(subscribe).execute().await.expect("should subscribe");
    assert_eq!(reply.status, StatusCode::OK);

    let body: SubscribeReply = reply.body;
    let mut event_stream = body.subscription;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let reader = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let message_cid = write.cid().expect("should have cid");

    let reply = alice_node.request(write).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the RecordsWrite event exists.
    // --------------------------------------------------
    let query = QueryBuilder::new().sign(alice).build().await.expect("should create query");
    let reply = alice_node.request(query).execute().await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // An anonymous use attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let mut subscribe = SubscribeBuilder::new().sign(alice).build().await.expect("should build");
    subscribe.authorization = Authorization::default();

    let Err(Error::BadRequest(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));

    // --------------------------------------------------
    // Bob attempts to subscribe to Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new().sign(bob).build().await.expect("should build");
    let Err(Error::Forbidden(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "missing permission grant");
}

// Should allow users to subscribe to events matching grant scope.
#[tokio::test]
async fn interface_scope() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to all her messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to subscribe to Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(subscribe).execute().await.expect("should subscribe");
    assert_eq!(reply.status, StatusCode::OK);

    let body: SubscribeReply = reply.body;
    let mut alice_events = body.subscription;

    // --------------------------------------------------
    // Alice writes a number of messages.
    // --------------------------------------------------
    let mut message_cids = vec![];

    // 1. configure 'allow-any' protocol
    let bytes = include_bytes!("../examples/protocols/allow-any.json");
    let definition = serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // 2. configure a random protocol
    let configure = ConfigureBuilder::new()
        .definition(Definition::new("http://random.xyz"))
        .sign(alice)
        .build()
        .await
        .expect("should build");

    message_cids.push(configure.cid().expect("should have cid"));

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // 3. write a record to the 'allow-any' protocol
    let reader = Cursor::new(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    message_cids.push(write.cid().expect("should have cid"));

    let reply = alice_node.request(write).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // 4. write a random record
    let reader = Cursor::new(br#"{"message": "test write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    message_cids.push(write.cid().expect("should have cid"));

    let reply = alice_node.request(write).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to write records scoped to the 'allow-any' protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://allow-any".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to subscribe to messages (and fails).
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "interface is not within grant scope");
}

// Should reject subscriptions when method is not authorized.
#[tokio::test]
async fn unauthorized_method() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice grants Bob permission to query messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to subscribe to messages (and fails).
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .permission_grant_id(bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "method is not within grant scope");
}

// Should allow subscribing to protocol filtered messages with matching protocol grant scopes.
#[tokio::test]
async fn protocol_filter() {
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("../examples/protocols/allow-any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to `protocol1` messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: Some("http://protocol1.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob subscribes to `protocol1` messages in Alice's event stream.
    // --------------------------------------------------
    let filter = MessagesFilter::new().protocol("http://protocol1.xyz");
    let subscribe = SubscribeBuilder::new()
        .add_filter(filter)
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(subscribe).execute().await.expect("should subscribe");
    assert_eq!(reply.status, StatusCode::OK);

    let body: SubscribeReply = reply.body;
    let mut alice_events = body.subscription;

    // --------------------------------------------------
    // Alice writes 2 records, the first to `protocol1` and the second to `protocol2`.
    // --------------------------------------------------
    // protocol1
    let reader = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://protocol1.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let protocol1_cid = write.cid().expect("should have cid");

    let reply = alice_node.request(write).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // protocol2
    let reader = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(reader))
        .protocol(ProtocolBuilder {
            protocol: "http://protocol2.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = alice_node.request(write).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
    let alice_node = alice_node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let bytes = include_bytes!("../examples/protocols/allow-any.json");
    let mut definition =
        serde_json::from_slice::<Definition>(bytes).expect("should parse protocol");

    // protocol1
    definition.protocol = "http://protocol1.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // protocol2
    definition.protocol = "http://protocol2.xyz".to_string();
    let configure = ConfigureBuilder::new()
        .definition(definition)
        .sign(alice)
        .build()
        .await
        .expect("should build");

    let reply = alice_node.request(configure).execute().await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to subscribe to `protocol1` messages.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(bob.did())
        .scope(Scope::Messages {
            method: Method::Subscribe,
            protocol: Some("http://protocol1.xyz".to_string()),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");

    let bob_grant_id = bob_grant.record_id.clone();

    let reply = alice_node.request(bob_grant).execute().await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob subscribes to `protocol2` messages in Alice's event stream.
    // --------------------------------------------------
    let subscribe = SubscribeBuilder::new()
        .add_filter(MessagesFilter::new().protocol("http://protocol2.xyz"))
        .permission_grant_id(&bob_grant_id)
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(subscribe).execute().await else {
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
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let Err(Error::Forbidden(e)) = alice_node.request(subscribe).execute().await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "filter and grant protocols do not match");
}
