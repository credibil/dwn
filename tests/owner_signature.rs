//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
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
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Bob writes a message to his web node
    // --------------------------------------------------
    let bob_data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let bob_write = WriteBuilder::new()
        .data(WriteData::Bytes {
            data: bob_data.clone(),
        })
        .published(true)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    let bob_reply =
        write::handle(BOB_DID, bob_write.clone(), &provider, Some(&mut bob_data.as_slice()))
            // let reply = write::handle(BOB_DID, write.clone(), provider.clone(), None::<&mut &[u8]>)
            .await
            .expect("should write");
    assert_eq!(bob_reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the message from Bob's web node
    // --------------------------------------------------
    let alice_read = ReadBuilder::new()
        .filter(RecordsFilter {
            record_id: Some(bob_write.record_id),
            ..RecordsFilter::default()
        })
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let alice_reply =
        read::handle(BOB_DID, alice_read.clone(), &provider).await.expect("should read");
    assert_eq!(alice_reply.status.code, StatusCode::OK);
    assert_snapshot!("read", alice_reply, {
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
    // Alice augments Bob's message as an external owner
    // --------------------------------------------------
    let Some(mut alice_signed) = alice_reply.entry.clone().records_write else {
        panic!("should have records write entry");
    };
    alice_signed.sign_as_owner(&alice_keyring).await.expect("should sign as owner");

    // --------------------------------------------------
    // Alice saves Bob's message to her DWN
    // --------------------------------------------------
    let alice_data = alice_reply.entry.data.as_ref().unwrap();
    let alice_reply =
        write::handle(ALICE_DID, alice_signed, &provider, Some(&mut alice_data.as_slice()))
            .await
            .expect("should write");
    assert_eq!(alice_reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob's message can be read from Alice's DWN
    // --------------------------------------------------
    let reply = read::handle(BOB_DID, alice_read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let alice_data = reply.entry.data.expect("should have data");
    //   expect(ArrayUtility.byteArraysEqual(dataFetched, dataBytes!)).to.be.true;
}
