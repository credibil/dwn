//! Author Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! another entity to perform an action on their behalf. In this case, Alice
//! grants Bob the ability to configure a protocol on her behalf.

use test_utils::store::ProviderImpl;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::protocols::{ConfigureBuilder, ProtocolDefinition, QueryBuilder};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::service::{Message, Reply};
use vercre_dwn::{Interface, Method};

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

#[tokio::test]
async fn configure() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Alice's keyring");

    // ------------------------------
    // Alice grants Bob the ability to configure any protocol
    // ------------------------------
    let builder = GrantBuilder::new()
        .granted_to(BOB_DID)
        .request_id("grant_id_1")
        .description("Allow Bob to configure any protocol")
        .delegated(true)
        .scope(Interface::Protocols, Method::Configure, None);

    let grant_to_bob = builder.build(&alice_keyring).await.expect("should create grant");

    // ------------------------------
    // Bob configures the email protocol on Alice's behalf
    // ------------------------------
    let email_json = include_bytes!("protocols/email.json");
    let email_proto: ProtocolDefinition =
        serde_json::from_slice(email_json).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(email_proto.clone())
        .delegated_grant(grant_to_bob)
        .build(&bob_keyring)
        .await
        .expect("should build");
    let message = Message::ProtocolsConfigure(configure);

    let reply = vercre_dwn::handle_message(ALICE_DID, message, provider.clone())
        .await
        .expect("should configure protocol");

    let Reply::ProtocolsConfigure(reply) = reply else {
        panic!("unexpected reply: {:?}", reply);
    };

    assert_eq!(reply.status.code, 202);

    // ------------------------------
    // Alice fetches the email protocol configured by Bob
    // ------------------------------
    let query = QueryBuilder::new()
        .filter(email_proto.protocol)
        .build(&alice_keyring)
        .await
        .expect("should build");
    let message = Message::ProtocolsQuery(query);

    let reply = vercre_dwn::handle_message(ALICE_DID, message, provider.clone())
        .await
        .expect("should find protocol");

    let Reply::ProtocolsQuery(reply) = reply else {
        panic!("unexpected reply: {:?}", reply);
    };

    assert_eq!(reply.status.code, 200);
}
