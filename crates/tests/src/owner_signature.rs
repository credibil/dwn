//! Owner Signature
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use std::io::Read;
use std::sync::LazyLock;

use dwn_node::endpoint;
use dwn_node::interfaces::records::{Data, ReadBuilder, RecordsFilter, WriteBuilder};
use http::StatusCode;
use serde_json::{Value, json};
use test_node::keystore::{self, Keyring};
use test_node::provider::ProviderImpl;

static ALICE: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static BOB: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());

// Use owner signature for authorization when it is provided.
#[tokio::test]
async fn flat_space() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // --------------------------------------------------
    // Bob writes a message to his web node
    // --------------------------------------------------
    let bob_data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let bob_msg = WriteBuilder::new()
        .data(Data::from(bob_data))
        .published(true)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(&BOB.did, bob_msg.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the message from Bob's web node
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&bob_msg.record_id);
    let alice_read =
        ReadBuilder::new().filter(filter).sign(&*ALICE).build().await.expect("should create write");

    let reply =
        endpoint::handle(&BOB.did, alice_read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let read_reply = reply.body.expect("should be records read");
    let mut read_bob_msg = read_reply.entry.records_write.expect("should have records write entry");
    assert_eq!(read_bob_msg.record_id, bob_msg.record_id);

    // --------------------------------------------------
    // Alice augments Bob's message and saves to her web node
    // --------------------------------------------------
    let alice_data = read_reply.entry.data.expect("should have data");
    read_bob_msg.sign_as_owner(&*ALICE).await.expect("should sign as owner");
    read_bob_msg.with_stream(alice_data);

    let reply = endpoint::handle(&ALICE.did, read_bob_msg, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob's message can be read from Alice's web node
    // --------------------------------------------------
    let reply = endpoint::handle(&BOB.did, alice_read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let read_reply = reply.body.expect("should be records read");
    let mut reader = read_reply.entry.data.expect("should have data");
    let mut alice_data = Vec::new();
    reader.read_to_end(&mut alice_data).expect("should read to end");

    let bob_data: Value = serde_json::from_slice(&alice_data).expect("should deserialize");
    assert_eq!(json! ({ "message": "test record write" }), bob_data);
}
