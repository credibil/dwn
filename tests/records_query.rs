//! Messages Subscribe

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use serde_json::json;
use vercre_dwn::data::DataStream;
use vercre_dwn::endpoint;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{QueryBuilder, RecordsFilter, WriteBuilder, WriteData};

// Query should return matching records.
#[tokio::test]
async fn find_matches() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes 3 records.
    // --------------------------------------------------
    let data = serde_json::to_vec(&json!({
        "message": "test record write",
    }))
    .expect("should serialize");
    let stream = WriteData::Reader(DataStream::from(data));

    let write = WriteBuilder::new()
        .data(stream.clone())
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write = WriteBuilder::new()
        .data(stream.clone())
        .data_format("novel_data_format")
        .schema("schema_1")
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write = WriteBuilder::new()
        .data(stream)
        .data_format("novel_data_format")
        .schema("schema_2")
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for records with matching format.
    // --------------------------------------------------
    let filter = RecordsFilter::new().add_author(ALICE_DID).data_format("novel_data_format");
    let query = QueryBuilder::new()
        .filter(filter)
        .build(&alice_keyring)
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}
