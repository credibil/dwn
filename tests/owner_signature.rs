//! Owner Signature
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use std::io::Read;

use dwn_test::keystore::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::{json, Value};
use vercre_dwn::data::DataStream;
use vercre_dwn::endpoint;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{ReadBuilder, RecordsFilter, WriteBuilder, WriteData};

// Use owner signature for authorization when it is provided.
#[tokio::test]
async fn flat_space() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Bob writes a message to his web node
    // --------------------------------------------------
    let bob_data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let bob_msg = WriteBuilder::new()
        .data(WriteData::Reader {
            reader: DataStream::from(bob_data),
        })
        .published(true)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(BOB_DID, bob_msg.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the message from Bob's web node
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(bob_msg.record_id);
    let alice_read =
        ReadBuilder::new().filter(filter).build(&alice_keyring).await.expect("should create write");

    let reply =
        endpoint::handle(BOB_DID, alice_read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert_snapshot!("alice_read", reply, {
        ".**.recordId" => "[recordId]",
        ".**.messageTimestamp" => "[messageTimestamp]",
        ".**.dateCreated" => "[dateCreated]",
        ".**.datePublished" => "[datePublished]",
        ".**.signature.payload" => "[payload]",
        ".**.signature.signatures[0].signature" => "[signature]",
        ".**.attestation.payload" => "[payload]",
        ".**.attestation.signatures[0].signature" => "[signature]",
        ".entry.data" => "[data]",
    });

    // --------------------------------------------------
    // Alice augments Bob's message and saves to her web node
    // --------------------------------------------------
    let read_reply = reply.body.expect("should be records read");
    let alice_data = read_reply.entry.data.expect("should have data");

    let mut bob_msg = read_reply.entry.records_write.expect("should have records write entry");
    bob_msg.sign_as_owner(&alice_keyring).await.expect("should sign as owner");
    bob_msg.with_stream(alice_data);

    let reply = endpoint::handle(ALICE_DID, bob_msg, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob's message can be read from Alice's web node
    // --------------------------------------------------
    let reply = endpoint::handle(BOB_DID, alice_read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let read_reply = reply.body.expect("should be records read");
    let mut reader = read_reply.entry.data.expect("should have data");
    let mut alice_data = Vec::new();
    reader.read_to_end(&mut alice_data).expect("should read to end");

    let bob_data: Value = serde_json::from_slice(&alice_data).expect("should deserialize");
    assert_snapshot!("bob_data", bob_data);
}
