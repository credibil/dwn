//! Message Read
//!
//! This test demonstrates how a web node owner create a message and
//! subsequently read it.

use base64ct::{Base64UrlUnpadded, Encoding};
use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use serde_json::json;
use vercre_dwn::data::{cid, DataStream};
// use vercre_dwn::messages::{QueryBuilder, ReadBuilder};
use vercre_dwn::permissions::{GrantBuilder, ScopeType};
// use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{WriteBuilder, WriteData};
use vercre_dwn::{endpoint, Interface, Method};

// Scenario:
// Alice gives Bob a grant allowing him to read any message in her DWN.
// Bob invokes that grant to read a message.
#[tokio::test]
#[ignore]
async fn read_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    // let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");

    let mut write = WriteBuilder::new()
        // .data(WriteData::Reader {
        //     reader: DataStream::from(data),
        // })
        .data(WriteData::Bytes { data: data.clone() })
        .published(true)
        .build(&alice_keyring)
        .await
        .expect("should create write");

    write.data_stream = Some(DataStream::from(data));

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

    // convert the encoded data to a stream
    // TODO: refactor this into a helper function
    let Some(encoded_data) = &bob_grant.encoded_data else {
        panic!("should have encoded data");
    };
    let data_bytes = Base64UrlUnpadded::decode_vec(encoded_data).expect("should decode");
    bob_grant.descriptor.data_cid = cid::from_value(&data_bytes).expect("should create CID");
    bob_grant.descriptor.data_size = data_bytes.len();
    bob_grant.data_stream = Some(DataStream::from(data_bytes));
    bob_grant.encoded_data = None;

    let reply = endpoint::handle(ALICE_DID, bob_grant, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // let bytes = serde_json::to_vec(&grant_to_bob).expect("should serialize");
    // let stream = DataStream::from(bytes);
    // let write=Write::from(&grant_to_bob);

    // const grantReply = await dwn.processMessage(alice.did, permissionGrant.recordsWrite.message, { dataStream: grantDataStream });
    // expect(grantReply.status.code).to.equal(202);

    // // --------------------------------------------------
    // // Alice configures a protocol.
    // // --------------------------------------------------
    // let allow_any = include_bytes!("../crates/dwn-test/protocols/allow_any.json");
    // let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    // let configure = ConfigureBuilder::new()
    //     .definition(definition.clone())
    //     .build(&alice_keyring)
    //     .await
    //     .expect("should build");

    // let mut expected_cids = vec![configure.cid().unwrap()];

    // let reply =
    //     endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    // assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // // --------------------------------------------------
    // // Alice queries for messages without a cursor, and expects to see
    // // all 5 records as well as the protocol configuration message.
    // // --------------------------------------------------
    // let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create write");
    // let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    // assert_eq!(reply.status.code, StatusCode::OK);

    // let query_reply = reply.body.expect("should be records read");
    // let entries = query_reply.entries.expect("should have entries");
    // assert_eq!(entries.len(), 6);

    // for entry in entries {
    //     assert!(expected_cids.contains(&entry));
    // }

    // // --------------------------------------------------
    // // Alice writes an additional record.
    // // --------------------------------------------------
    // let message = WriteBuilder::new()
    //     .protocol(protocol.clone())
    //     .schema(&schema)
    //     // .data(WriteData::Bytes { data: data.clone() })
    //     .data(WriteData::Reader { reader })
    //     .published(true)
    //     .build(&alice_keyring)
    //     .await
    //     .expect("should create write");

    // expected_cids.push(message.cid().unwrap());

    // let reply = endpoint::handle(ALICE_DID, message, &provider).await.expect("should write");
    // assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // // --------------------------------------------------
    // // Alice queries for messages beyond the cursor, and
    // // expects to see only the additional record.
    // // --------------------------------------------------
    // // TODO: implement cursor
    // let query = QueryBuilder::new().build(&alice_keyring).await.expect("should create query");
    // let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    // assert_eq!(reply.status.code, StatusCode::OK);

    // let query_reply = reply.body.expect("should be records read");
    // let entries = query_reply.entries.expect("should have entries");
    // assert_eq!(entries.len(), 7);

    // // --------------------------------------------------
    // // Alice reads one of the returned messages.
    // // --------------------------------------------------
    // let read = ReadBuilder::new()
    //     .message_cid(&entries[0])
    //     .build(&alice_keyring)
    //     .await
    //     .expect("should create read");
    // let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    // assert_eq!(reply.status.code, StatusCode::OK);
}
