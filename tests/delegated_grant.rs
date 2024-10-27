//! Delegated grant test

use test_utils::store::ProviderImpl;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::protocols::{ConfigureBuilder, ProtocolDefinition, QueryBuilder};
use vercre_dwn::service::{Message, Reply};
use vercre_dwn::{Interface, Method};
use vercre_infosec::KeyOps;

const ALICE_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const BOB_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

#[tokio::test]
async fn configure() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let builder = GrantBuilder::new(ALICE_DID.to_string())
        .issued_to(BOB_DID.to_string())
        .request_id("grant_id_1".to_string())
        .description("Allow Bob to configure the email protocol".to_string())
        .delegated(true)
        .scope(Interface::Protocols, Method::Configure, None);
    let grant = builder.build(&provider).await.expect("should create grant");

    // println!("{:?}", grant);

    let email_json = include_bytes!("protocols/email.json");
    let email_proto: ProtocolDefinition =
        serde_json::from_slice(email_json).expect("should deserialize");

    // println!("{:?}", email_proto);

    // Bob should be able to configure a protocol on Alice's behalf
    let signer = provider.signer(BOB_DID).expect("should get signer");
    let configure = ConfigureBuilder::new()
        .definition(email_proto.clone())
        .delegated_grant(grant)
        .build(&signer)
        .await
        .expect("should build");
    let message = Message::ProtocolsConfigure(configure);

    let reply = vercre_dwn::handle_message(ALICE_DID, message, provider.clone())
        .await
        .expect("should configure protocol");

    let Reply::ProtocolsConfigure(reply) = reply else {
        panic!("unexpected reply: {:?}", reply);
    };
    assert_eq!(reply.status.code, 200);

    // verify the protocol configure message was processed
    let signer = provider.signer(ALICE_DID).expect("should get signer");
    let query = QueryBuilder::new()
        .filter(email_proto.protocol)
        .build(&signer)
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
