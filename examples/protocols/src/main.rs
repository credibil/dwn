use base64ct::{Base64UrlUnpadded, Encoding};
use dwn_test::keystore::ALICE_DID;
use dwn_test::store::ProviderImpl;
use serde_json::json;
use vercre_dwn::endpoint;
use vercre_dwn::protocols::Query;
use vercre_dwn::provider::{KeyStore, Signer};

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

    let keyring = KeyStore::keyring(&provider, ALICE_DID).expect("should get keyring");
    let sig_bytes =
        keyring.try_sign(format!("{protected}.{payload}").as_bytes()).await.expect("should sign");
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
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should send message");

    println!("{:?}", reply);
}
