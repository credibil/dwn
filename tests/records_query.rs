//! Messages Subscribe

use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{QueryBuilder, RecordsFilter, Sort, Write, WriteBuilder, WriteData};
use vercre_dwn::{Error, endpoint};

// Should return a status of BadRequest (400) when querying for unpublished records
// with sort date set to `Sort::Publishedxxx`.
#[tokio::test]
async fn invalid_sort() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().published(false))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");

    query.descriptor.date_sort = Some(Sort::PublishedAscending);
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, query.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "cannot sort by `date_published` when querying for unpublished records");

    query.descriptor.date_sort = Some(Sort::PublishedDescending);
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, query, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "cannot sort by `date_published` when querying for unpublished records");
}

// Should return `record_id`, `descriptor`, `authorization` and `attestation` fields.
#[tokio::test]
async fn return_values() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());

    let write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .data_format("awesome_data_format")
        .attest(&[&bob_keyring])
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for records with matching format.
    // --------------------------------------------------
    let filter = RecordsFilter::new().add_author(ALICE_DID).data_format("awesome_data_format");
    let query = QueryBuilder::new()
        .filter(filter)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    assert_snapshot!("return_values", entries[0].write, {
        ".recordId" => "[recordId]",
        ".descriptor.messageTimestamp" => "[messageTimestamp]",
        ".descriptor.dateCreated" => "[dateCreated]",
        ".authorization.signature.payload" => "[payload]",
        ".authorization.signature.signatures[0].signature" => "[signature]",
        ".attestation.payload" => "[payload]",
        ".attestation.signatures[0].signature" => "[signature]",
    });
}

// Should return matching records.
#[tokio::test]
async fn find_matches() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes 3 records.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());

    for i in 1..=3 {
        let mut builder = WriteBuilder::new().data(WriteData::Reader(stream.clone()));

        if i > 1 {
            builder = builder.data_format("awesome_data_format").schema(format!("schema_{i}"));
        }

        let write = builder.sign(&alice_keyring).build().await.expect("should create write");
        let reply = endpoint::handle(ALICE_DID, write, &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for records with matching format.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_format("awesome_data_format"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice queries for records with matching schema.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_format("awesome_data_format").schema("schema_2"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should return `encoded_data` if data size is within the spec threshold.
#[tokio::test]
async fn encoded_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());

    let write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `encoded_data`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];
    assert!(entry.write.encoded_data.is_some());
}

// Should return `encoded_data` if data size is within the spec threshold.
#[tokio::test]
async fn no_encoded_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `encoded_data`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];
    assert!(entry.write.encoded_data.is_none());
}
