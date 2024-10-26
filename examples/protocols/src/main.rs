use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use test_utils::keystore::{Keystore, OWNER_DID};
use test_utils::store::ProviderImpl;
use vercre_dwn::service::Message;

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // JWS JSON serialization
    let payload = Base64UrlUnpadded::encode_string(
        br#"{"descriptorCid":"PeFcHaKaNZL9RRntKPySMmhGLE2sM9lVu8Q4kcw","permissionGrantId":"grant_id_1"}"#,
    );

    let protected = Base64UrlUnpadded::encode_string(
        br#"{"alg":"EdDSA","typ":"jwt","kid":"did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX#z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX"}"#
    );
    let sig_bytes =
        Keystore::try_sign(format!("{protected}.{payload}").as_bytes()).expect("should sign");
    let signature = Base64UrlUnpadded::encode_string(&sig_bytes);

    // Query message
    let query_json = json!({
        "descriptor": {
            "interface": "Protocols",
            "method": "Query",
            "filter": {
                "protocol": "https://decentralized-social-example.org/protocol/"
            }
        },
        "authorization": {
            "signature": {
                "payload": payload,
                "signatures": [{
                    "protected": protected,
                    "signature": signature
                }]
            }
        }
    });

    let query = serde_json::from_value(query_json).expect("should deserialize");
    let msg = Message::ProtocolsQuery(query);
    let reply =
        vercre_dwn::handle_message(OWNER_DID, msg, provider).await.expect("should send message");

    println!("{:?}", reply);
}
