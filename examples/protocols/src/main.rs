use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_dwn::client::protocols::Query;
use credibil_dwn::{Signer, endpoint};
use serde_json::json;
use test_node::{ProviderImpl, keystore};

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = keystore::new_keyring();

    // JWS JSON serialization
    let payload = Base64UrlUnpadded::encode_string(
        br#"{"descriptorCid":"PeFcHaKaNZL9RRntKPySMmhGLE2sM9lVu8Q4kcw","permissionGrantId":"grant_id_1"}"#,
    );

    let protected = Base64UrlUnpadded::encode_string(
        br#"{"alg":"EdDSA","typ":"jwt","kid":"did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX#z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX"}"#
    );
    let sig_bytes =
        alice.try_sign(format!("{protected}.{payload}").as_bytes()).await.expect("should sign");
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

    let query: Query = serde_json::from_value(query_json).expect("should deserialize");
    let reply = endpoint::handle(&alice.did, query, &provider).await.expect("should send message");

    println!("{:?}", reply);
}
