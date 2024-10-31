//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use serde_json::json;
use test_utils::store::ProviderImpl;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::protocols::{ConfigureBuilder, ProtocolDefinition, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{DelegatedGrant, WriteBuilder, WriteData};
use vercre_dwn::service::{Message, Reply};
use vercre_dwn::{Interface, Method};

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

// Use `ownerignature` for authorization when it is provided.
#[tokio::test]
async fn flat_space() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Alice's keyring");

    // ------------------------------
    // Bob writes a message to his web node
    // ------------------------------
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

    let message = Message::RecordsWrite(write);
    let reply =
        vercre_dwn::handle_message(BOB_DID, message, provider.clone()).await.expect("should write");
    let Reply::RecordsWrite(reply) = reply else {
        panic!("unexpected reply: {:?}", reply);
    };
    assert_eq!(reply.status.code, 202);

    // ------------------------------
    // Alice fetches the message from Bob's web node
    // ------------------------------
    // const recordsRead = await RecordsRead.create({
    //     filter : { recordId: message.recordId },
    //     signer : Jws.createSigner(alice)
    //   });

    //   const readReply = await dwn.processMessage(bob.did, recordsRead.message);
    //   expect(readReply.status.code).to.equal(200);
    //   expect(readReply.entry!.recordsWrite).to.exist;
    //   expect(readReply.entry!.recordsWrite?.descriptor).to.exist;

    // let builder = GrantBuilder::new()
    //     .granted_to(BOB_DID)
    //     .request_id("grant_id_1")
    //     .description("Allow Bob to configure any protocol")
    //     .delegated(true)
    //     .scope(Interface::Protocols, Method::Configure, None);

    // let grant_to_bob = builder.build(&alice_keyring).await.expect("should create grant");

    // // ------------------------------
    // // Bob configures the email protocol on Alice's behalf
    // // ------------------------------
    // let email_json = include_bytes!("protocols/email.json");
    // let email_proto: ProtocolDefinition =
    //     serde_json::from_slice(email_json).expect("should deserialize");

    // let configure = ConfigureBuilder::new()
    //     .definition(email_proto.clone())
    //     .delegated_grant(grant_to_bob)
    //     .build(&bob_keyring)
    //     .await
    //     .expect("should build");

    // let message = Message::ProtocolsConfigure(configure);
    // let reply = vercre_dwn::handle_message(ALICE_DID, message, provider.clone())
    //     .await
    //     .expect("should configure protocol");

    // let Reply::ProtocolsConfigure(reply) = reply else {
    //     panic!("unexpected reply: {:?}", reply);
    // };

    // assert_eq!(reply.status.code, 202);

    // // ------------------------------
    // // Alice fetches the email protocol configured by Bob
    // // ------------------------------
    // let query = QueryBuilder::new()
    //     .filter(email_proto.protocol)
    //     .build(&alice_keyring)
    //     .await
    //     .expect("should build");

    // let message = Message::ProtocolsQuery(query);
    // let reply = vercre_dwn::handle_message(ALICE_DID, message, provider.clone())
    //     .await
    //     .expect("should find protocol");

    // let Reply::ProtocolsQuery(reply) = reply else {
    //     panic!("unexpected reply: {:?}", reply);
    // };

    // assert_eq!(reply.status.code, 200);
}
