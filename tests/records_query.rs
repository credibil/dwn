//! Messages Subscribe

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{QueryBuilder, RecordsFilter, Sort, WriteBuilder, WriteData};
use vercre_dwn::{Error, endpoint};

// Should return a status of BadRequest (400) when querying for unpublished records
// with sort date set to `Sort::DatePublished`.
#[tokio::test]
async fn invalid_sort() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().published(false))
        .build(&alice_keyring)
        .await
        .expect("should create query");
    query.descriptor.date_sort = Some(Sort::PublishedAscending);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "cannot sort by `date_published` when querying for unpublished records");
}

// Should return matching records.
#[tokio::test]
async fn find_matches() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes 3 records.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let stream = WriteData::Reader(DataStream::from(data.to_vec()));

    let write = WriteBuilder::new()
        .data(stream.clone())
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    for i in 1..=2 {
        let write = WriteBuilder::new()
            .data(stream.clone())
            .data_format("novel_data_format")
            .schema(format!("schema_{i}"))
            .build(&alice_keyring)
            .await
            .expect("should create write");
        let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

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
