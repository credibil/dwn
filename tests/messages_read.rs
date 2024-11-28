//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

use base64ct::{Base64UrlUnpadded, Encoding};
use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use serde_json::json;
use vercre_dwn::data::DataStream;
use vercre_dwn::messages::ReadBuilder;
use vercre_dwn::permissions::{GrantBuilder, ScopeType};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData};
use vercre_dwn::{endpoint, Interface, Message, Method};

// Scenario:
// Alice gives Bob a grant allowing him to read any message in her DWN.
// Bob invokes that grant to read a message.
#[tokio::test]
#[ignore]
async fn read_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let write = WriteBuilder::new()
        .data(WriteData::Reader {
            reader: DataStream::from(data),
        })
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice issues a grant allowing Bob to read any record in her web node.
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB_DID)
        .request_id("grant_id_1")
        .description("allow Bob to read messages")
        .expires_in(60 * 60 * 24)
        .scope(Interface::Messages, Method::Read, ScopeType::Protocols { protocol: None });
    let mut bob_grant = builder.build(&alice_keyring).await.expect("should create grant");

    // TODO: help function
    let Some(encoded_data) = &bob_grant.encoded_data else {
        panic!("should have encoded data");
    };
    let data_bytes = Base64UrlUnpadded::decode_vec(encoded_data).expect("should decode");
    let stream = DataStream::from(data_bytes);
    let (cid, size) = stream.compute_cid().expect("should have cid");
    bob_grant.descriptor.data_cid = cid;
    bob_grant.descriptor.data_size = size;
    bob_grant.data_stream = Some(stream);
    // bob_grant.encoded_data = None;

    let record_id = bob_grant.record_id.clone();
    let message_cid = bob_grant.cid().expect("should get CID");

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob invokes that grant to read a record from Alice's web node.
    // --------------------------------------------------
    // const messagesRead = await TestDataGenerator.generateMessagesRead({
    //   author            : bob,
    //   permissionGrantId : permissionGrant.recordsWrite.message.recordId,
    //   messageCid,
    // });
    // const readReply = await dwn.processMessage(alice.did, messagesRead.message);
    // expect(readReply.status.code).to.equal(200);
    // expect(readReply.entry).to.not.be.undefined;
    // expect(readReply.entry!.messageCid).to.equal(messageCid);

    let read = ReadBuilder::new()
        .message_cid(message_cid)
        .permission_grant_id(record_id)
        .build(&bob_keyring)
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    println!("{:?}", reply);

    // assert_eq!(reply.status.code, StatusCode::OK);
}
