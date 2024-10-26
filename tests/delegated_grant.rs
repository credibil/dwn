//! Delegated grant test

use test_utils::store::ProviderImpl;
use test_utils::test_data;
use vercre_dwn::permissions::GrantBuilder;
use vercre_dwn::protocols::Definition as ProtocolDefinition;
use vercre_dwn::service::Message;
use vercre_dwn::{Interface, Method};

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

    println!("{:?}", grant);

    let email_json = include_bytes!("protocols/email.json");
    let email_proto: ProtocolDefinition =
        serde_json::from_slice(email_json).expect("should deserialize");

    println!("{:?}", email_proto);

    // Bob attempts to configure a protocol
    let input = test_data::ConfigureInput {
        delegated_grant: Some(grant),
        author: Some(test_data::Persona {
            did: BOB_DID.to_string(),
        }),
        protocol_definition: Some(email_proto),
        ..test_data::ConfigureInput::default()
    };

    let configure = test_data::protocols_configure(input).await.expect("should configure protocol");
    let message = Message::ProtocolsConfigure(configure.message);

    // Bob should be able to configure a protocol on Alice's behalf
    let _reply = vercre_dwn::handle_message(ALICE_DID, message, provider)
        .await
        .expect("should configure protocol");

    // // JWS JSON serialization
    // let payload = Base64UrlUnpadded::encode_string(
    //     br#"{"descriptorCid":"PeFcHaKaNZL9RRntKPySMmhGLE2sM9lVu8Q4kcw","permissionGrantId":"grant_id_1"}"#,
    // );

    // let protected = Base64UrlUnpadded::encode_string(
    //     br#"{"alg":"EdDSA","typ":"jwt","kid":"did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX#z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX"}"#
    // );
    // let sig_bytes =
    //     keystore::try_sign(format!("{protected}.{payload}").as_bytes()).expect("should sign");
    // let signature = Base64UrlUnpadded::encode_string(&sig_bytes);

    // // Query message
    // let query_json = json!({
    //     "descriptor": {
    //         "interface": "Protocols",
    //         "method": "Query",
    //         "filter": {
    //             "protocol": "https://decentralized-social-example.org/protocol/"
    //         }
    //     },
    //     "authorization": {
    //         "signature": {
    //             "payload": payload,
    //             "signatures": [{
    //                 "protected": protected,
    //                 "signature": signature
    //             }]
    //         }
    //     }
    // });

    // let query = serde_json::from_value(query_json).expect("should deserialize");
    // let msg = Message::ProtocolsQuery(query);
    // let reply =
    //     vercre_dwn::handle_message(OWNER_DID, msg, provider).await.expect("should send message");

    // println!("{:?}", reply);
}
