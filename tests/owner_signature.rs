//! Owner Signature
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use std::io::Read;

use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::{json, Value};
use test_utils::store::ProviderImpl;
use vercre_dwn::handlers::{read, write};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{ReadBuilder, RecordsFilter, WriteBuilder, WriteData};

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

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
        .data(WriteData::Bytes {
            data: bob_data.clone(),
        })
        .published(true)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let reply = write::handle(BOB_DID, bob_msg.clone(), &provider, Some(&mut bob_data.as_slice()))
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the message from Bob's web node
    // --------------------------------------------------
    let filter = RecordsFilter {
        record_id: Some(bob_msg.record_id),
        ..RecordsFilter::default()
    };
    let alice_read =
        ReadBuilder::new().filter(filter).build(&alice_keyring).await.expect("should create write");

    let reply = read::handle(BOB_DID, alice_read.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert_snapshot!("alice_read", reply, {
        ".entry.recordsWrite.recordId" => "[recordId]",
        ".entry.recordsWrite.descriptor.messageTimestamp" => "[messageTimestamp]",
        ".entry.recordsWrite.descriptor.dateCreated" => "[dateCreated]",
        ".entry.recordsWrite.descriptor.datePublished" => "[datePublished]",
        ".entry.recordsWrite.authorization.signature.payload" => "[payload]",
        ".entry.recordsWrite.authorization.signature.signatures[0].signature" => "[signature]",
        ".entry.recordsWrite.attestation.payload" => "[payload]",
        ".entry.recordsWrite.attestation.signatures[0].signature" => "[signature]",
        ".entry.data" => "[data]",
    });

    // --------------------------------------------------
    // Alice augments Bob's message and saves to her web node
    // --------------------------------------------------
    let Some(mut bob_msg) = reply.entry.records_write else {
        panic!("should have records write entry");
    };
    bob_msg.sign_as_owner(&alice_keyring).await.expect("should sign as owner");

    let mut reader = reply.entry.data.expect("should have data");
    let mut alice_data = Vec::new();
    reader.read_to_end(&mut alice_data).expect("should read to end");

    let reply = write::handle(ALICE_DID, bob_msg, &provider, Some(&mut alice_data.as_slice()))
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob's message can be read from Alice's web node
    // --------------------------------------------------
    let reply = read::handle(BOB_DID, alice_read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let mut reader = reply.entry.data.expect("should have data");
    let mut alice_data = Vec::new();
    reader.read_to_end(&mut alice_data).expect("should read to end");

    let bob_data: Value = serde_json::from_slice(&alice_data).expect("should deserialize");
    assert_snapshot!("bob_data", bob_data);
}
