//! Owner Signature
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use http::StatusCode;
// use insta::assert_yaml_snapshot as assert_snapshot;
// use serde_json::{json, Value};
use test_utils::store::ProviderImpl;
use vercre_dwn::messages::{self, query, QueryBuilder};
use vercre_dwn::provider::KeyStore;

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
// const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

// Use owner signature for authorization when it is provided.
#[tokio::test]
async fn all_messages() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    // let bob_keyring = provider.keyring(BOB_DID).expect("should get Alice's keyring");

    // scenario: Alice configures a protocol, and writes 5 records.

    // --------------------------------------------------
    // Alice queries for messages without a cursor, and expects to see
    // all 5 records as well as the protocol configuration message.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .add_filter(messages::Filter {
            protocol: Some("vercre_dwn".to_string()),
            ..Default::default()
        })
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = query::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    // --------------------------------------------------
    // Alice writes an additional record.
    // --------------------------------------------------
    // let filter = RecordsFilter {
    //     record_id: Some(bob_msg.record_id),
    //     ..RecordsFilter::default()
    // };
    // let alice_read =
    //     ReadBuilder::new().filter(filter).build(&alice_keyring).await.expect("should create write");

    // let reply = read::handle(BOB_DID, alice_read.clone(), &provider).await.expect("should read");
    // assert_eq!(reply.status.code, StatusCode::OK);
    // assert_snapshot!("alice_read", reply, {
    //     ".entry.recordsWrite.recordId" => "[recordId]",
    //     ".entry.recordsWrite.descriptor.messageTimestamp" => "[messageTimestamp]",
    //     ".entry.recordsWrite.descriptor.dateCreated" => "[dateCreated]",
    //     ".entry.recordsWrite.descriptor.datePublished" => "[datePublished]",
    //     ".entry.recordsWrite.authorization.signature.payload" => "[payload]",
    //     ".entry.recordsWrite.authorization.signature.signatures[0].signature" => "[signature]",
    //     ".entry.recordsWrite.attestation.payload" => "[payload]",
    //     ".entry.recordsWrite.attestation.signatures[0].signature" => "[signature]",
    //     ".entry.data" => "[data]",
    // });

    // --------------------------------------------------
    // Alice queries for messages beyond the cursor, and
    // expects to see only the additional record.
    // --------------------------------------------------
    // let Some(mut bob_msg) = reply.entry.records_write else {
    //     panic!("should have records write entry");
    // };
    // bob_msg.sign_as_owner(&alice_keyring).await.expect("should sign as owner");

    // let alice_data = reply.entry.data.expect("should have data");
    // let reply = write::handle(ALICE_DID, bob_msg, &provider, Some(&mut alice_data.as_slice()))
    //     .await
    //     .expect("should write");
    // assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // // --------------------------------------------------
    // // Bob's message can be read from Alice's web node
    // // --------------------------------------------------
    // let reply = read::handle(BOB_DID, alice_read, &provider).await.expect("should read");
    // assert_eq!(reply.status.code, StatusCode::OK);

    // let alice_data = reply.entry.data.expect("should have data");
    // let bob_data: Value = serde_json::from_slice(&alice_data).expect("should deserialize");
    // assert_snapshot!("bob_data", bob_data);
}
