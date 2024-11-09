//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_utils::store::ProviderImpl;
use vercre_dwn::handlers::{read, write};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{ReadBuilder, ReadReply, RecordsFilter, WriteBuilder, WriteData};
use vercre_dwn::service::Reply;

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
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let write = WriteBuilder::new()
        .data(WriteData::Bytes { data })
        .published(true)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    // dataStream
    // let reply = vercre_dwn::handle_message(BOB_DID, write.clone(), provider.clone())
    //     .await
    //     .expect("should write");
    let reply =
        write::handle(BOB_DID, write.clone(), provider.clone()).await.expect("should write");
    assert_eq!(reply.status().code, 204);

    // --------------------------------------------------
    // Alice fetches the message from Bob's web node
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter {
            record_id: Some(write.record_id),
            ..RecordsFilter::default()
        })
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = read::handle(BOB_DID, read, provider.clone()).await.expect("should write");
    assert_eq!(reply.status().code, 200);

    assert_snapshot!("read", reply, {
        ".entry.recordsWrite.recordId" => "[recordId]",
        ".entry.recordsWrite.descriptor.messageTimestamp" => "[messageTimestamp]",
        ".entry.recordsWrite.descriptor.dateCreated" => "[dateCreated]",
        ".entry.recordsWrite.descriptor.datePublished" => "[datePublished]",
        ".entry.recordsWrite.authorization.signature.payload" => "[payload]",
        ".entry.recordsWrite.authorization.signature.signatures[0].signature" => "[signature]",
        ".entry.recordsWrite.attestation.payload" => "[payload]",
        ".entry.recordsWrite.attestation.signatures[0].signature" => "[signature]",
    });

    // --------------------------------------------------
    // Alice augments Bob's message as an external owner
    // --------------------------------------------------
    //   const { entry } = readReply; // remove data from message
    let Some(read_reply) = reply.as_any().downcast_ref::<ReadReply>() else {
        panic!("should downcast to ReadReply");
    };
    let Some(mut owner_signed) = read_reply.entry.clone().records_write else {
        panic!("should have records write entry");
    };
    owner_signed.sign_as_owner(&alice_keyring).await.expect("should sign as owner");

    // --------------------------------------------------
    // Alice saves Bob's message to her DWN
    // --------------------------------------------------
    // let data = read_reply.entry.data.as_ref().unwrap();
    // let bytes = serde_json::to_vec(&data).expect("should serialize");
    // let encoded = Base64UrlUnpadded::encode_string(&bytes);

    // owner_signed.encoded_data = Some(encoded);

    // let reply = vercre_dwn::handle_message(ALICE_DID, owner_signed, provider.clone())
    //     .await
    //     .expect("should write");
    // assert_eq!(reply.status().code, 202);

    //   const aliceDataStream = readReply.entry!.data!;
    //   const aliceWriteReply = await dwn.processMessage(alice.did, owner_signed, { dataStream: aliceDataStream });
    //   expect(aliceWriteReply.status.code).to.equal(202);

    // --------------------------------------------------
    // Bob's message can be read from Alice's DWN
    // --------------------------------------------------
    //   const readReply2 = await dwn.processMessage(alice.did, recordsRead.message);
    //   expect(readReply2.status.code).to.equal(200);
    //   expect(readReply2.entry!.recordsWrite).to.exist;
    //   expect(readReply2.entry!.recordsWrite?.descriptor).to.exist;

    //   const dataFetched = await DataStream.toBytes(readReply2.entry!.data!);
    //   expect(ArrayUtility.byteArraysEqual(dataFetched, dataBytes!)).to.be.true;
}
