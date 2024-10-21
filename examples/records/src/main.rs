use serde_json::json;
use test_utils::store::ProviderImpl;
use vercre_dwn::auth::Authorization;
use vercre_dwn::protocols::{self};
use vercre_dwn::service::Message;

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    let authorization = json!({
        "signature": {
            "payload": "eyJkZXNjcmlwdG9yQ2lkIjogIlBlRmNIYUthTlpMOVJSbnRLUHlTTW1oR0xFMnNNOWxWdThRNGtjdyIsInBlcm1pc3Npb25HcmFudElkIjoiZ3JhbnRfaWRfMSJ9",
            "signatures": [
                {
                    "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0Iiwia2lkIjoiZGlkOmtleTp6Nk1rajhKcjFyZzNZalZXV2hnN2FoRVlKaWJxaGpCZ1p0MXBEQ2JUNEx2N0Q0SFgjejZNa2o4SnIxcmczWWpWV1doZzdhaEVZSmlicWhqQmdadDFwRENiVDRMdjdENEhYIn0",
                    "signature": "5678nr67e56g45wf546786n9t78r67e45657bern797t8r6e5"
                }
            ]
        }
    });

    let mut query = protocols::Query::default();
    query.descriptor.filter = Some(protocols::query::Filter {
        protocol: "https://decentralized-social-example.org/protocol/".to_string(),
    });
    query.authorization = serde_json::from_value(authorization).expect("should deserialize");

    let msg = Message::ProtocolsQuery(query);

    let reply =
        vercre_dwn::handle_message("tenant", msg, provider).await.expect("should send message");
    println!("{:?}", reply);
}
