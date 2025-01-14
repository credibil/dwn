//! Records Write

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use dwn_test::key_store::{
    ALICE_DID, ALICE_VERIFYING_KEY, APP_DID as ISSUER_DID, APP_DID as PFI_DID, BOB_DID, CAROL_DID,
    CAROL_DID as FAKE_DID,
};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use rand::RngCore;
use vercre_dwn::authorization::JwsPayload;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::hd_key::{DerivationScheme, PrivateKeyJwk};
use vercre_dwn::messages::{self, MessagesFilter};
use vercre_dwn::permissions::{Conditions, GrantBuilder, Publication, RecordsScope, Scope};
use vercre_dwn::protocols::{ConfigureBuilder, Definition, ProtocolType, RuleSet};
use vercre_dwn::provider::{EventLog, KeyStore};
use vercre_dwn::records::{
    Attestation, Data, DeleteBuilder, EncryptOptions, ProtocolBuilder, QueryBuilder, ReadBuilder,
    Recipient, RecordsFilter, SignaturePayload, WriteBuilder,
};
use vercre_dwn::store::MessagesQuery;
use vercre_dwn::{Error, Interface, Message, Method, Range, data, endpoint};
use vercre_infosec::jose::{Curve, JwsBuilder, KeyType, PublicKeyJwk};

// // Should handle pre-processing errors
// #[tokio::test]
// async fn pre_process() {}

// Should be able to update existing record when update has a later `message_timestamp`.
#[tokio::test]
async fn update_older() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let data = b"a new write record";

    let initial = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(data)));

    // --------------------------------------------------
    // Update the existing record.
    // --------------------------------------------------
    let data = b"updated write record";

    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the updated record overwrote the original.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&update.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(data)));

    // --------------------------------------------------
    // Attempt to overwrite the latest record with an older version.
    // --------------------------------------------------
    let Err(Error::Conflict(e)) = endpoint::handle(ALICE_DID, initial, &provider).await else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "a more recent update exists");

    // --------------------------------------------------
    // Verify the latest update remains unchanged.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(update.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(data)));
}

// Should be able to update existing record with identical message_timestamp
// only when message CID is larger than the existing one.
#[tokio::test]
async fn update_smaller_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"a new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Create 2 records with the same `message_timestamp`.
    // --------------------------------------------------
    // let message_timestamp = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();
    let message_timestamp = initial.descriptor.base.message_timestamp + Duration::seconds(1);

    let write_1 = WriteBuilder::from(initial.clone())
        .data(Data::from(b"message 1".to_vec()))
        .message_timestamp(message_timestamp.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let write_2 = WriteBuilder::from(initial.clone())
        .data(Data::from(b"message 2".to_vec()))
        .message_timestamp(message_timestamp.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // determine the order of the writes by CID size
    let mut sorted = vec![write_1.clone(), write_2.clone()];
    sorted.sort_by(|a, b| a.cid().unwrap().cmp(&b.cid().unwrap()));

    // --------------------------------------------------
    // Update the initial record with the first update (ordered by CID size).
    // --------------------------------------------------
    let reply =
        endpoint::handle(ALICE_DID, sorted[0].clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // verify update
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.descriptor.data_cid, sorted[0].descriptor.data_cid);

    // --------------------------------------------------
    // Apply the second update (ordered by CID size).
    // --------------------------------------------------
    let reply =
        endpoint::handle(ALICE_DID, sorted[1].clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // verify update
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.descriptor.data_cid, sorted[1].descriptor.data_cid);

    // --------------------------------------------------
    // Attempt to update using the first update (smaller CID) update and fail.
    // --------------------------------------------------
    let Err(Error::Conflict(e)) = endpoint::handle(ALICE_DID, sorted[0].clone(), &provider).await
    else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "an update with a larger CID already exists");
}

// Should allow data format of a flat-space record to be updated to any value.
#[tokio::test]
async fn update_flat_space() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"a new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record with a new data format.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(b"update write record".to_vec()))
        .data_format("a-new-data-format")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the data format has been updated.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.descriptor.data_format, update.descriptor.data_format);
}

// Should not allow immutable properties to be updated.
#[tokio::test]
async fn immutable_unchanged() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let date_created = Utc::now();

    let update = WriteBuilder::new()
        .record_id(initial.record_id.clone())
        .date_created(date_created)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "immutable properties do not match");

    // --------------------------------------------------
    // Verify `schema` cannot be updated.
    // --------------------------------------------------
    let update = WriteBuilder::new()
        .record_id(initial.record_id.clone())
        .schema("new-schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "immutable properties do not match");
}

// Should inherit data from previous write when `data_cid` and `data_size`
// match and no data stream is provided.
#[tokio::test]
async fn inherit_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record, providing data to calculate CID and size, but without
    // adding to block store.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the initial write and it's data are still available.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&update.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(b"some data")));
}

// ln 367: Should allow an initial write without data.
#[tokio::test]
async fn initial_no_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record with no data.
    // --------------------------------------------------
    let initial =
        WriteBuilder::new().sign(&alice_keyring).build().await.expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Verify the record cannot be queried for.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // --------------------------------------------------
    // Update the record, adding data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(b"update write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the data format has been updated.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"update write record"))
    );
}

// ln 409: Should not allow a record to be updated without data.
#[tokio::test]
async fn update_no_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record, providing data to calculate CID and size, but without
    // setting `data_stream`.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::Bytes(b"update write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "data CID does not match descriptor `data_cid`");

    // --------------------------------------------------
    // Verify the initial write and it's data are still available.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(b"some data")));
}

// Should inherit data from previous writes when data size greater than
// `encoded_data` threshold.
#[tokio::test]
async fn retain_large_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record with a lot of data.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let initial = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record but not data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the initial write's data is still available.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
    let read_stream = body.entry.data.expect("should have data");
    assert_eq!(read_stream.buffer, data.to_vec());
}

// Should inherit data from previous writes when data size less than
// `encoded_data` threshold.
#[tokio::test]
async fn retain_small_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record with a lot of data.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let initial = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record but not data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the initial write's data is still available.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
    let read_stream = body.entry.data.expect("should have data");
    assert_eq!(read_stream.buffer, data.to_vec());
}

// Should fail when data size greater than `encoded_data` threshold and
// descriptor `data_size` is larger than data size.
#[tokio::test]
async fn large_data_size_larger() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a lot of data and then change the `data_size`.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data size
    write.descriptor.data_size = MAX_ENCODED_SIZE + 100;
    write.record_id = write.entry_id(ALICE_DID).expect("should create record ID");
    write.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data size does not match message `data_size`");
}

// Should fail when data size less than `encoded_data` threshold and descriptor
// `data_size` is larger than `encoded_data` threshold.
#[tokio::test]
async fn small_data_size_larger() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a small amount of data and then change the `data_size`.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data size
    write.descriptor.data_size = MAX_ENCODED_SIZE + 100;
    write.record_id = write.entry_id(ALICE_DID).expect("should create record ID");
    write.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data size does not match message `data_size`");
}

// Should fail when data size greater than `encoded_data` threshold and
// descriptor `data_size` is smaller than threshold.
#[tokio::test]
async fn large_data_size_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a lot of data and then change the `data_size`.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data size
    write.descriptor.data_size = 1;
    write.record_id = write.entry_id(ALICE_DID).expect("should create record ID");
    write.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data size does not match message `data_size`");
}

// Should fail when data size less than `encoded_data` threshold and descriptor
// `data_size` is smaller than actual data size.
#[tokio::test]
async fn small_data_size_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a small amount of data and then change the `data_size`.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data size and recalculate the `record_id` and signature
    write.descriptor.data_size = 1;
    write.record_id = write.entry_id(ALICE_DID).expect("should create record ID");
    write.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data size does not match message `data_size`");
}

// Should fail when data size greater than `encoded_data` threshold and
// descriptor `data_cid` is incorrect.
#[tokio::test]
async fn large_data_cid_larger() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a lot of data and then change the `data_cid`.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());
    write.data_stream = Some(write_stream);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data CID does not match message `data_cid`");
}

// Should fail when data size less than `encoded_data` threshold and descriptor
// `data_cid` is incorrect.
#[tokio::test]
async fn small_data_cid_larger() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a small amount of data and then change the `data_cid`.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());
    write.data_stream = Some(write_stream);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data CID does not match message `data_cid`");
}

// Should fail when data size greater than `encoded_data` threshold and
// descriptor `data_cid` is incorrect.
#[tokio::test]
async fn large_data_cid_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a lot of data and then change the `data_cid`.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());
    write.data_stream = Some(write_stream);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data CID does not match message `data_cid`");
}

// Should fail when data size less than `encoded_data` threshold and descriptor
// `data_cid` is incorrect.
#[tokio::test]
async fn small_data_cid_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Writes a record with a small amount of data and then change the `data_cid`.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = DataStream::from(data.to_vec());
    write.data_stream = Some(write_stream);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data CID does not match message `data_cid`");
}

// Should prevent accessing data by referencing a different `data_cid` in an
// update.
#[tokio::test]
async fn alter_data_cid_larger() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write 2 records.
    // --------------------------------------------------
    // record 1
    let mut data_1 = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data_1);

    let write_1 = WriteBuilder::new()
        .data(Data::from(data_1.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // record 2
    let mut data_2 = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data_2);

    let write_2 = WriteBuilder::new()
        .data(Data::from(data_2.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Attempt to update record 2 to reference record 1's data.
    // --------------------------------------------------
    let mut update = WriteBuilder::from(write_2.clone())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    update.descriptor.data_cid = write_1.descriptor.data_cid;
    update.descriptor.data_size = write_1.descriptor.data_size;

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "data CID does not match descriptor `data_cid`");

    // --------------------------------------------------
    // Verify record still has original data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write_2.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let data = body.entry.data.expect("should have data");
    assert_eq!(data.buffer, data_2.to_vec());
}

// Should prevent accessing data by referencing a different`data_cid` in an update.
#[tokio::test]
async fn alter_data_cid_smaller() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write 2 records.
    // --------------------------------------------------
    // record 1
    let mut data_1 = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data_1);

    let write_1 = WriteBuilder::new()
        .data(Data::from(data_1.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // record 2
    let mut data_2 = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data_2);

    let write_2 = WriteBuilder::new()
        .data(Data::from(data_2.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Attempt to update record 2 to reference record 1's data.
    // --------------------------------------------------
    let mut update = WriteBuilder::from(write_2.clone())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the data CID
    update.descriptor.data_cid = write_1.descriptor.data_cid;
    update.descriptor.data_size = write_1.descriptor.data_size;

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "data CID does not match descriptor `data_cid`");

    // --------------------------------------------------
    // Verify record still has original data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write_2.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let data = body.entry.data.expect("should have data");
    assert_eq!(data.buffer, data_2.to_vec());
}

// Should allow updates without specifying `data` or `date_published`.
#[tokio::test]
async fn update_published_no_date() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record's `published` state has been updated.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .build()
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"new write record"))
    );
}

// Should conserve `published` state when updating using an existing Write record.
#[tokio::test]
async fn update_published() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(b"update write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record's `published` state has been updated.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.descriptor.published, Some(true));
    assert_eq!(
        entries[0].write.descriptor.date_published.unwrap().timestamp_micros(),
        initial.descriptor.date_published.unwrap().timestamp_micros()
    );
}

// Should fail when updating a record but its initial write cannot be found.
#[tokio::test]
async fn no_initial_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .record_id("bafkreihs5gnovjoqueffglvevvohpgts3aj5ykgmlqm7quuotujxtxtp7f")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, initial, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "initial write not found");
}

// Should fail when creating a record if `date_created` and `message_timestamp`
// do not match.
#[tokio::test]
async fn create_date_mismatch() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let created = DateTime::parse_from_rfc3339("2025-01-01T00:00:00-00:00").unwrap();

    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .date_created(created.into())
        .message_timestamp(Utc::now())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, initial, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "`message_timestamp` and `date_created` do not match");
}

// Should fail when creating a record with an invalid `context_id`.
#[tokio::test]
async fn invalid_context_id() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let mut initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    initial.context_id =
        Some("bafkreihs5gnovjoqueffglvevvohpgts3aj5ykgmlqm7quuotujxtxtp7f".to_string());

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, initial, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "invalid context ID");
}

// Should log an event on initial write.
#[tokio::test]
async fn log_initial_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify an event was logged.
    // --------------------------------------------------
    let query = messages::QueryBuilder::new()
        .add_filter(MessagesFilter::new().interface(Interface::Records))
        .build(&alice_keyring)
        .await
        .expect("should create query");

    let query = MessagesQuery::from(query);
    let (events, _) =
        EventLog::query(&provider, ALICE_DID, &query.into()).await.expect("should fetch");
    assert_eq!(events.len(), 1);
}

// Should only ever retain (at most) the initial and most recent writes.
#[tokio::test]
async fn retain_two_writes() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record and 2 updates.
    // --------------------------------------------------
    let data = b"a new write record";
    let initial = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let update1 = WriteBuilder::from(initial.clone())
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, update1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let update2 = WriteBuilder::from(initial.clone())
        .date_published(Utc::now())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, update2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify only the initial write and latest update remain.
    // --------------------------------------------------
    let query = messages::QueryBuilder::new()
        .add_filter(MessagesFilter::new().interface(Interface::Records))
        .build(&alice_keyring)
        .await
        .expect("should create query");

    let query = MessagesQuery::from(query);
    let (events, _) =
        EventLog::query(&provider, ALICE_DID, &query.into()).await.expect("should fetch");
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].cid(), initial.cid());
    assert_eq!(events[1].cid(), update2.cid());
}

// Should allow anyone to create a record using the "anyone create" rule.
#[tokio::test]
async fn anyone_create() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes an email.
    // --------------------------------------------------
    let email = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, email.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the email from Bob.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&email.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"Hello Alice"))
    );
}

// Should allow anyone to create a record using the "anyone co-update" rule.
#[tokio::test]
async fn anyone_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a collaboration protocol.
    // --------------------------------------------------
    let collab = include_bytes!("../crates/dwn-test/protocols/anyone-collaborate.json");
    let definition: Definition = serde_json::from_slice(collab).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a document.
    // --------------------------------------------------
    let alice_doc = WriteBuilder::new()
        .data(Data::from(b"A document".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://anyone-collaborate-protocol.xyz",
            protocol_path: "doc",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_doc.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob updates Alice's document.
    // --------------------------------------------------
    let alice_doc = WriteBuilder::from(alice_doc)
        .data(Data::from(b"An update".to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_doc, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create a new document.
    // --------------------------------------------------
    let bob_doc = WriteBuilder::new()
        .data(Data::from(b"A document".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://anyone-collaborate-protocol.xyz",
            protocol_path: "doc",
            parent_context_id: None,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_doc, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow creating records using an ancestor recipient rule.
#[tokio::test]
async fn ancestor_create() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let issuer_keyring = provider.keyring(ISSUER_DID).expect("should get VC issuer's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a credential application to her web node to simulate a
    // credential application being sent to a VC issuer.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, application.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // The VC Issuer responds to Alice's request.
    // --------------------------------------------------
    let response = WriteBuilder::new()
        .data(Data::from(b"credential response data".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialResponse",
            parent_context_id: application.context_id,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-response")
        .data_format("application/json")
        .sign(&issuer_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, response.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify VC Issuer's response was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&response.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"credential response data"))
    );
}

// Should allow creating records using an ancestor recipient rule.
#[tokio::test]
async fn ancestor_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a recipient protocol.
    // --------------------------------------------------
    let recipient = include_bytes!("../crates/dwn-test/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a post with Bob as the recipient.
    // --------------------------------------------------
    let alice_post = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://recipient-can-protocol.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_post.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a post tag.
    // --------------------------------------------------
    let alice_tag = WriteBuilder::new()
        .data(Data::from(b"tag my post".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://recipient-can-protocol.xyz",
            protocol_path: "post/tag",
            parent_context_id: alice_post.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_tag.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob updates Alice's post.
    // --------------------------------------------------
    let bob_tag = WriteBuilder::from(alice_tag.clone())
        .data(Data::from(b"Bob's tag".to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_tag.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create a new post.
    // --------------------------------------------------
    let bob_tag = WriteBuilder::new()
        .data(Data::from(b"Bob's post".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://recipient-can-protocol.xyz",
            protocol_path: "post/tag",
            parent_context_id: alice_post.context_id,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_tag.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow updates using a direct recipient rule.
#[tokio::test]
async fn direct_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a recipient protocol.
    // --------------------------------------------------
    let recipient = include_bytes!("../crates/dwn-test/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a post with Bob as the recipient.
    // --------------------------------------------------
    let alice_post = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://recipient-can-protocol.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_post.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol attempts (but fails) to update Alice's post.
    // --------------------------------------------------
    let carol_update = WriteBuilder::from(alice_post.clone())
        .data(Data::from(b"Carol's update".to_vec()))
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) =
        endpoint::handle(ALICE_DID, carol_update.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob updates Alice's post.
    // --------------------------------------------------
    let bob_update = WriteBuilder::from(alice_post.clone())
        .data(Data::from(b"Bob's update".to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow author to block non-authors using an ancestor author rule.
#[tokio::test]
async fn block_non_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Bob configures the social media protocol.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&bob_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(BOB_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an image to Bob's web node.
    // --------------------------------------------------
    let alice_image = WriteBuilder::new()
        .data(Data::from(b"cafe-aesthetic.jpg".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image",
            parent_context_id: None,
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, alice_image.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol attempts (but fails) to add a caption to Alice's image.
    // --------------------------------------------------
    let carol_caption = WriteBuilder::new()
        .data(Data::from(b"bad vibes! >:(".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image/caption",
            parent_context_id: None,
        })
        .schema("captionSchema")
        .data_format("text/plain")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) =
        endpoint::handle(BOB_DID, carol_caption.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Alice adds a caption to her image.
    // --------------------------------------------------
    let alice_caption = WriteBuilder::new()
        .data(Data::from(b"coffee and work vibes!".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image/caption",
            parent_context_id: alice_image.context_id,
        })
        .schema("captionSchema")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, alice_caption.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify Alice was able to add her caption.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&alice_caption.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(BOB_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"coffee and work vibes!"))
    );
}

// Should allow author to update using an ancestor author rule.
#[tokio::test]
async fn ancestor_author_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the author-can protocol.
    // --------------------------------------------------
    let author_can = include_bytes!("../crates/dwn-test/protocols/author-can.json");
    let definition: Definition = serde_json::from_slice(author_can).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob creates a post.
    // --------------------------------------------------
    let bob_post = WriteBuilder::new()
        .data(Data::from(b"Bob's post".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://author-can-protocol.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_post.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice comments on Bob's post
    // --------------------------------------------------
    let alice_comment = WriteBuilder::new()
        .data(Data::from(b"Alice's comment".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://author-can-protocol.xyz",
            protocol_path: "post/comment",
            parent_context_id: bob_post.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_comment.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob updates Alice's comment
    // --------------------------------------------------
    let bob_update = WriteBuilder::from(alice_comment)
        .data(Data::from(b"Update to Alice's comment".to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create a new comment on his post.
    // --------------------------------------------------
    let bob_post = WriteBuilder::new()
        .data(Data::from(b"Bob's comment".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://author-can-protocol.xyz",
            protocol_path: "post/comment",
            parent_context_id: bob_post.context_id,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_post.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow a role record with recipient to be created and updated.
#[tokio::test]
async fn update_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates Bob's friend role record.
    // --------------------------------------------------
    let update = WriteBuilder::from(bob_friend)
        .data(Data::from(b"Bob is still my friend".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should reject a role record when no recipient is defined.
#[tokio::test]
async fn no_role_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to add a role record with no recipient.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "role record is missing recipient");
}

// Should allow a role record to be created for the same recipient after their
// previous record has been deleted.
#[tokio::test]
async fn recreate_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice removes Bob as a friend.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&bob_friend.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");
    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should delete");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend again.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend again".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow records to be created and updated using a context role.
#[tokio::test]
async fn context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates Bob's role.
    // --------------------------------------------------
    let update_bob = WriteBuilder::from(bob_thread)
        .data(Data::from(b"Update Bob".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, update_bob.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow the same role to be created under different contexts.
#[tokio::test]
async fn context_roles() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread1 = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, thread1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread1 = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread1.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts another thread.
    // --------------------------------------------------
    let thread2 = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, thread2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the second thread.
    // --------------------------------------------------
    let bob_thread2 = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread2.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should reject attempts to create a duplicate role under same context.
#[tokio::test]
async fn duplicate_context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to add Bob to the thread again.
    // --------------------------------------------------
    let bob_thread2 = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) =
        endpoint::handle(ALICE_DID, bob_thread2.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "recipient already has this role record");
}

// Should allow a context role record to be created for the same recipient
// after their previous record has been deleted.
#[tokio::test]
async fn recreate_context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice removes Bob from the thread.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&bob_thread.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");
    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should delete");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice re-adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread2 = WriteBuilder::new()
        .data(Data::from(b"Bob can rejoin my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow a creating records using role-based permissions.
#[tokio::test]
async fn role_can_create() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob write a chat record.
    // --------------------------------------------------
    let bob_chat = WriteBuilder::new()
        .data(Data::from(b"Bob is Alice's friend".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .protocol_role("friend")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow a updating records using role-based permissions.
#[tokio::test]
async fn role_can_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "admin",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a chat record.
    // --------------------------------------------------
    let alice_chat = WriteBuilder::new()
        .data(Data::from(b"Bob is Alice's friend".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses his 'admin' role to update the chat thread.
    // --------------------------------------------------
    let bob_update = WriteBuilder::from(alice_chat)
        .data(Data::from(b"I'm more than a friend".to_vec()))
        .protocol_role("admin")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should reject record creation if the recipient has not been assigned the
// protocol role.
#[tokio::test]
async fn invalid_protocol_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a friend.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is my friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "admin",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_friend.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a chat record.
    // --------------------------------------------------
    let alice_chat = WriteBuilder::new()
        .data(Data::from(b"Bob is Alice's friend".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to use the 'chat' role because it does not exist.
    // --------------------------------------------------
    let bob_chat = WriteBuilder::new()
        .data(Data::from(b"I'm more than a friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .protocol_role("chat")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_chat.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "protocol path does not match role record type");
}

// Should reject record creation if the author has not been assigned the
// protocol role being used.
#[tokio::test]
async fn unassigned_protocol_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../crates/dwn-test/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to use the 'friend' role because it has not
    // been assigned to him.
    // --------------------------------------------------
    let bob_chat = WriteBuilder::new()
        .data(Data::from(b"I'm more than a friend".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .protocol_role("friend")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_chat.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should allow record creation for authorized context role.
#[tokio::test]
async fn create_protocol_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob write a chat record.
    // --------------------------------------------------
    let bob_chat = WriteBuilder::new()
        .data(Data::from(b"Bob is Alice's friend".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .protocol_role("thread/participant")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow record updates for authorized context role.
#[tokio::test]
async fn update_protocol_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the friend-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"My new thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/admin",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice write a chat record.
    // --------------------------------------------------
    let alice_chat = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob write a chat record.
    // --------------------------------------------------
    let bob_chat = WriteBuilder::from(alice_chat)
        .data(Data::from(b"Hello wonderful Bob".to_vec()))
        .protocol_role("thread/admin")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should reject creation of records when no access has been granted to the
// protocol role path.
#[tokio::test]
async fn forbidden_role_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice starts a new thread.
    // --------------------------------------------------
    let thread1 = WriteBuilder::new()
        .data(Data::from(b"Thread one".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, thread1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob to the thread.
    // --------------------------------------------------
    let bob_thread = WriteBuilder::new()
        .data(Data::from(b"Bob can join my thread".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread1.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_thread.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a second thread.
    // --------------------------------------------------
    let thread2 = WriteBuilder::new()
        .data(Data::from(b"Thread two".to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, thread2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to write a chat record to the second thread.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread2.context_id.clone(),
        })
        .protocol_role("thread/participant")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, chat.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should reject creation of records using an invalid protocol path.
#[tokio::test]
async fn invalid_role_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the thread-role protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../crates/dwn-test/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to use a fake protocol role.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .protocol_role("not-a-real-path")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, chat.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no rule set defined for invoked role");
}

// Should allow record updates by the initial author.
#[tokio::test]
async fn initial_author_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the message protocol.
    // --------------------------------------------------
    let message = include_bytes!("../crates/dwn-test/protocols/message.json");
    let definition: Definition = serde_json::from_slice(message).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a message.
    // --------------------------------------------------
    let bob_msg = WriteBuilder::new()
        .data(Data::from(b"Hello from Bob".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://message-protocol.xyz",
            protocol_path: "message",
            parent_context_id: None,
        })
        .schema("http://message.me")
        .data_format("text/plain")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_msg.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_msg.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, query.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"Hello from Bob"))
    );

    // --------------------------------------------------
    // Bob updates his message.
    // --------------------------------------------------
    let update = WriteBuilder::from(bob_msg)
        .data(Data::from(b"Hello, this is your friend Bob".to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the update.
    // --------------------------------------------------
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"Hello, this is your friend Bob"))
    );
}

// Should prevent record updates by another author who does not have permission.
#[tokio::test]
async fn no_author_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures the message protocol.
    // --------------------------------------------------
    let message = include_bytes!("../crates/dwn-test/protocols/message.json");
    let definition: Definition = serde_json::from_slice(message).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a message.
    // --------------------------------------------------
    let bob_msg = WriteBuilder::new()
        .data(Data::from(b"Hello from Bob".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://message-protocol.xyz",
            protocol_path: "message",
            parent_context_id: None,
        })
        .schema("http://message.me")
        .data_format("text/plain")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_msg.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_msg.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, query.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"Hello from Bob"))
    );

    // --------------------------------------------------
    // Carol attempts (but fails) to update Bob's message.
    // --------------------------------------------------
    let update = WriteBuilder::new()
        .data(Data::from(b"Hello, this is your friend Carol".to_vec()))
        .record_id(bob_msg.record_id)
        .protocol(ProtocolBuilder {
            protocol: "http://message-protocol.xyz",
            protocol_path: "message",
            parent_context_id: None,
        })
        .schema("http://message.me")
        .data_format("text/plain")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should prevent updates to the immutable `recipient` property.
#[tokio::test]
async fn no_recipient_update() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures the message protocol.
    // --------------------------------------------------
    let message = include_bytes!("../crates/dwn-test/protocols/message.json");
    let definition: Definition = serde_json::from_slice(message).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a message.
    // --------------------------------------------------
    let bob_msg = WriteBuilder::new()
        .data(Data::from(b"Hello from Bob".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://message-protocol.xyz",
            protocol_path: "message",
            parent_context_id: None,
        })
        .schema("http://message.me")
        .data_format("text/plain")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_msg.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_msg.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, query.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"Hello from Bob"))
    );

    // --------------------------------------------------
    // Bob attempts (but fails) to update the message's recipient.
    // --------------------------------------------------
    let update = WriteBuilder::new()
        .data(Data::from(b"Hello, this is your friend Carol".to_vec()))
        .record_id(bob_msg.record_id)
        .protocol(ProtocolBuilder {
            protocol: "http://message-protocol.xyz",
            protocol_path: "message",
            parent_context_id: None,
        })
        .schema("http://message.me")
        .data_format("text/plain")
        .recipient(CAROL_DID)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "immutable properties do not match");
}

// Should prevent unauthorized record creation using a `recipient` rule.
#[tokio::test]
async fn unauthorized_create() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let fake_keyring = provider.keyring(FAKE_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a credential application to her web node to simulate a
    // credential application being sent to a VC issuer.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, application.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // A fake VC Issuer responds to Alice's request.
    // --------------------------------------------------
    let response = WriteBuilder::new()
        .data(Data::from(b"credential response data".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialResponse",
            parent_context_id: application.context_id,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-response")
        .data_format("application/json")
        .sign(&fake_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, response, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should prevent record creation when protocol cannot be found.
#[tokio::test]
async fn no_protocol_definition() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a credential application to her web node without the
    // credential issuance protocol installed.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find protocol definition");
}

// Should prevent record creation when schema is invalid.
#[tokio::test]
async fn invalid_schema() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a credential application using an invalid schema.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication",
            parent_context_id: None,
        })
        .schema("unexpected-schema")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid schema");
}

// Should prevent record creation when protocol path is invalid.
#[tokio::test]
async fn invalid_protocol_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a credential application using an invalid protocol path.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "invalidType",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid protocol path");
}

// Should prevent record creation when protocol path is incorrect.
// That is, the path is valid but it is used incorrectly.
#[tokio::test]
async fn incorrect_protocol_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a credential application using an invalid protocol path.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ISSUER_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialResponse",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid protocol path for parentless record");
}

// Should prevent use of invalid data formats for a given protocol.
#[tokio::test]
async fn invalid_data_format() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures the social media protocol.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an image to her web node.
    // --------------------------------------------------
    let image = WriteBuilder::new()
        .data(Data::from(b"cafe-aesthetic.jpg".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image",
            parent_context_id: None,
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, image.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to update the image to an invalid format.
    // --------------------------------------------------
    let update = WriteBuilder::from(image.clone())
        .data_format("not-permitted-data-format")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid data format");

    // --------------------------------------------------
    // Alice updates the image to a permitted data format.
    // --------------------------------------------------
    let update = WriteBuilder::from(image.clone())
        .data_format("image/gif")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the data format was updated.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&image.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
    let write = body.entry.records_write.expect("should exist");
    assert_eq!(write.descriptor.data_format, "image/gif");
}

// Should allow any data format when protocol does not explicitly specify
// permitted data format(s).
#[tokio::test]
async fn any_data_format() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an image to her web node.
    // --------------------------------------------------
    let image = WriteBuilder::new()
        .data(Data::from(b"cafe-aesthetic.jpg".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .schema("any-schema")
        .data_format("any-data-format")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, image.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the image to another format.
    // --------------------------------------------------
    let update = WriteBuilder::from(image.clone())
        .data_format("any-new-data-format")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the data format was updated.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&image.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");

    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
    let write = body.entry.records_write.expect("should exist");
    assert_eq!(write.descriptor.data_format, "any-new-data-format");
}

// Should notnallow a record to be created when it's schema is invalid for the
// specified hierarchal level.
#[tokio::test]
async fn schema_hierarchy() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a credential issuance protocol.
    // --------------------------------------------------
    let issuance = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
    let definition: Definition = serde_json::from_slice(issuance).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to write a credential response with the
    // protocol path as a top-level path.
    // --------------------------------------------------
    let response1 = WriteBuilder::new()
        .data(Data::from(b"credential response data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialResponse",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-response")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, response1, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid protocol path");

    // --------------------------------------------------
    // Alice successfully writes a credential application.
    // --------------------------------------------------
    let application1 = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication",
            parent_context_id: None,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, application1.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to write a credential application below her
    // first application.
    // --------------------------------------------------
    let application2 = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialApplication",
            parent_context_id: application1.context_id.clone(),
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application2, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid protocol path");

    // --------------------------------------------------
    // Alice successfully writes a credential response.
    // --------------------------------------------------
    let response2 = WriteBuilder::new()
        .data(Data::from(b"credential response data".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialResponse",
            parent_context_id: application1.context_id,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-response")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, response2.clone(), &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to write a credential application below the
    // credential response.
    // --------------------------------------------------
    let application3 = WriteBuilder::new()
        .data(Data::from(b"credential application data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://credential-issuance-protocol.xyz",
            protocol_path: "credentialApplication/credentialResponse/credentialApplication",
            parent_context_id: response2.context_id,
        })
        .schema("https://identity.foundation/credential-manifest/schemas/credential-application")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, application3, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "invalid protocol path");
}

// Should only allow owner to write when record does not have an action rule
// defined.
#[tokio::test]
async fn owner_no_rule() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a private protocol.
    // --------------------------------------------------
    let private = include_bytes!("../crates/dwn-test/protocols/private-protocol.json");
    let definition: Definition = serde_json::from_slice(private).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice can write to her web node.
    // --------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://private-protocol.xyz",
            protocol_path: "privateNote",
            parent_context_id: None,
        })
        .schema("private-note")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to write to ALice's web node.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://private-protocol.xyz",
            protocol_path: "privateNote",
            parent_context_id: None,
        })
        .schema("private-note")
        .data_format("text/plain")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_write.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no rule defined for action");
}

// Should find recipient-based rules for deeply nested contexts.
#[tokio::test]
async fn deep_nesting() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let pfi_keyring = provider.keyring(PFI_DID).expect("should get the PFI keyring");

    // --------------------------------------------------
    // PFI configures the dex protocol.
    // --------------------------------------------------
    let dex = include_bytes!("../crates/dwn-test/protocols/dex.json");
    let definition: Definition = serde_json::from_slice(dex).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&pfi_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(PFI_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Setup:
    //  - Alice uses the tbDEX protocol to make a request to a
    //    Participating Financial Institution (PFI)
    //  - The PFI responds to Alice's request with an offer.
    // --------------------------------------------------
    let alice_ask = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .recipient(PFI_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://dex.xyz",
            protocol_path: "ask",
            parent_context_id: None,
        })
        .schema("https://tbd/website/tbdex/ask")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(PFI_DID, alice_ask.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // offer response
    let pfi_offer = WriteBuilder::new()
        .data(Data::from(b"some offer".to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://dex.xyz",
            protocol_path: "ask/offer",
            parent_context_id: alice_ask.context_id,
        })
        .schema("https://tbd/website/tbdex/offer")
        .sign(&pfi_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(PFI_DID, pfi_offer.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // The test:
    //  - Alice responds to the PFI acknowledging fulfillment of the offer.
    // --------------------------------------------------
    let fulfillment = WriteBuilder::new()
        .data(Data::from(b"some offer".to_vec()))
        .recipient(PFI_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://dex.xyz",
            protocol_path: "ask/offer/fulfillment",
            parent_context_id: pfi_offer.context_id,
        })
        .schema("https://tbd/website/tbdex/fulfillment")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(PFI_DID, fulfillment.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&fulfillment.record_id))
        .sign(&pfi_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(PFI_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.descriptor.data_cid, fulfillment.descriptor.data_cid);
}

// Should not permit write with invalid `parent_id`.
#[tokio::test]
async fn invalid_parent_id() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let pfi_keyring = provider.keyring(PFI_DID).expect("should get the PFI keyring");

    // --------------------------------------------------
    // PFI configures the dex protocol.
    // --------------------------------------------------
    let dex = include_bytes!("../crates/dwn-test/protocols/dex.json");
    let definition: Definition = serde_json::from_slice(dex).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&pfi_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(PFI_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice uses the tbDEX protocol to make a request to a Participating
    // Financial Institution (PFI)
    // --------------------------------------------------
    let alice_ask = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .recipient(PFI_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://dex.xyz",
            protocol_path: "ask",
            parent_context_id: None,
        })
        .schema("https://tbd/website/tbdex/ask")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(PFI_DID, alice_ask.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempt (and fails) to respond to the PFI to acknowledge
    // fulfillment without having received a response.
    // --------------------------------------------------
    let fulfillment = WriteBuilder::new()
        .data(Data::from(b"some offer".to_vec()))
        .recipient(PFI_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://dex.xyz",
            protocol_path: "ask/offer/fulfillment",
            parent_context_id: Some("nonexistentparentid".to_string()),
        })
        .schema("https://tbd/website/tbdex/fulfillment")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(PFI_DID, fulfillment.clone(), &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no parent record found");
}

// Should fail when CID for encrypted data does not match authorization `encryption_cid`.
#[tokio::test]
async fn invalid_encryption_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Setup: Alice's keys.
    // --------------------------------------------------
    let alice_kid = format!("{ALICE_DID}#z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX");

    // derive x25519 key from ed25519 key (Edwards -> Montgomery)
    let verifying_bytes: [u8; 32] =
        Base64UrlUnpadded::decode_vec(ALICE_VERIFYING_KEY).unwrap().try_into().unwrap();
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&verifying_bytes).unwrap();
    let alice_public = x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());

    let alice_private_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(alice_public.as_bytes()),
            ..PublicKeyJwk::default()
        },
        d: "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30".to_string(),
    };

    // --------------------------------------------------
    // Alice configures an email protocol with encryption.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let definition = definition
        .add_encryption(&alice_kid, alice_private_jwk.clone())
        .expect("should add encryption");

    let email = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, email, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Bob writes an encrypted email to Alice.
    // --------------------------------------------------
    // generate data and encrypt
    let data = "Hello Alice".as_bytes().to_vec();
    let mut options = EncryptOptions::new().data(&data);
    let mut encrypted = options.encrypt2().expect("should encrypt");
    let ciphertext = encrypted.ciphertext.clone();

    // get the rule set for the protocol path
    let rule_set = definition.structure.get("email").unwrap();
    let encryption = rule_set.encryption.as_ref().unwrap();

    // protocol path derived public key
    encrypted = encrypted.add_recipient(Recipient {
        key_id: alice_kid.clone(),
        public_key: encryption.public_key_jwk.clone(),
        derivation_scheme: DerivationScheme::ProtocolPath,
    });

    // generate data and encrypt
    let mut encryption = encrypted.finalize().expect("should encrypt");

    // create Write record
    let mut write = WriteBuilder::new()
        .data(Data::from(ciphertext))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .encryption(encryption.clone())
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");

    // cause the `encryption_cid` to be invalid
    encryption.initialization_vector = "invalid-iv".to_string();
    write.encryption = Some(encryption);

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "message and authorization `encryptionCid`s do not match");
}

// Should fail when protocol is not normalized.
#[tokio::test]
#[ignore = "the protocol is automatically normalized"]
async fn protocol_not_normalized() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an email.
    // --------------------------------------------------
    let mut email = WriteBuilder::new()
        .data(Data::from(b"Hello".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "example.com/",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    email.descriptor.protocol = Some("example.com/".to_string());
    email.record_id = email.entry_id(ALICE_DID).expect("should create record ID");
    email.context_id = Some(email.record_id.clone());
    email.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, email, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find protocol definition");
}

// Should prevent accessing data by referencing a different `data_cid` in
// protocol-authorized records.
#[tokio::test]
async fn small_data_cid_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a private record.
    // --------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"some private data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a social media protocol that allows anyone to read and
    // write images.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob learns the `data_cid` of Alice's record and attempts to gain access
    // by writing to Alice's web node using an open protocol that references
    // Alice's `data_cid` without providing any data.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::Cid {
            data_cid: alice_write.descriptor.data_cid.clone(),
            data_size: alice_write.descriptor.data_size.clone(),
        })
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image",
            parent_context_id: None,
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Verify Bob's record cannot be read.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record");

    // --------------------------------------------------
    // Verify Bob's record cannot be queried.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("imageSchema"))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // --------------------------------------------------
    //  Bob attempts (and fails) to publish his record without data.
    // --------------------------------------------------
    let bob_update = WriteBuilder::from(bob_write)
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, bob_update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "referenced data does not exist");
}

// FIXME: requires refactor of BlockStore -> DataStore

// Should prevent accessing data by referencing a different `data_cid` in
// protocol-authorized records with large amount of data.
#[tokio::test]
#[ignore]
async fn large_data_cid_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a private record with a large amount of data.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let alice_write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice configures a social media protocol that allows anyone to read and
    // write images.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob learns the metadata (including data_cid) of Alice's private record.
    // He attempts to gain access by writing to Alice's web node using an open
    // protocol that references Alice's data_cid without providing any data.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::Cid {
            data_cid: alice_write.descriptor.data_cid.clone(),
            data_size: alice_write.descriptor.data_size.clone(),
        })
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image",
            parent_context_id: None,
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Verify Bob's record cannot be read.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record");

    // --------------------------------------------------
    // Verify Bob's record cannot be queried.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("imageSchema"))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // --------------------------------------------------
    //  Bob attempts (and fails) to publish his record without data.
    // --------------------------------------------------
    let bob_update = WriteBuilder::from(bob_write)
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, bob_update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "referenced data does not exist");
}

// Should allow writes both with and without schema set when protocol does not
// require a schema.
#[tokio::test]
async fn protocol_schema() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a collaboration protocol that allows records to be
    // created both with and without schemas.
    // --------------------------------------------------
    let collaborate = include_bytes!("../crates/dwn-test/protocols/anyone-collaborate.json");
    let definition: Definition = serde_json::from_slice(collaborate).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record without a schema.
    // --------------------------------------------------
    let no_schema = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://anyone-collaborate-protocol.xyz",
            protocol_path: "doc",
            parent_context_id: None,
        })
        .data_format("application/octet-stream")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, no_schema.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record with a schema.
    // --------------------------------------------------
    let with_schema = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://anyone-collaborate-protocol.xyz",
            protocol_path: "doc",
            parent_context_id: None,
        })
        .schema("random-schema")
        .data_format("application/octet-stream")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, with_schema.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify Bob's record cannot be queried.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("imageSchema"))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol_path("doc"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should allow writes within the message size bounds specified in the protocol.
#[tokio::test]
async fn protocol_size_range() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a custom protocol with data size rules.
    // --------------------------------------------------
    let definition = Definition::new("http://blob-size.xyz")
        .published(true)
        .add_type("blob", ProtocolType::default())
        .add_rule("blob", RuleSet {
            size: Some(Range {
                min: Some(1),
                max: Some(1000),
            }),
            ..RuleSet::default()
        });

    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record at the minimum size.
    // --------------------------------------------------
    let mut data = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let min_size = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, min_size, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record at the maximum size.
    // --------------------------------------------------
    let mut data = [0u8; 1000];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let max_size = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, max_size, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record greater than the maximum size.
    // --------------------------------------------------
    let mut data = [0u8; 1001];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let too_big = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, too_big, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "data size is greater than allowed");
}

// Should fail authorization if protocol message size is less than specified
// minimum size.
#[tokio::test]
async fn protocol_min_size() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a custom protocol with data size rules.
    // --------------------------------------------------
    let definition = Definition::new("http://blob-size.xyz")
        .published(true)
        .add_type("blob", ProtocolType::default())
        .add_rule("blob", RuleSet {
            size: Some(Range {
                min: Some(1000),
                max: None,
            }),
            ..RuleSet::default()
        });

    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record below the minimum size.
    // --------------------------------------------------
    let mut data = [0u8; 999];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let too_small = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, too_small, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "data size is less than allowed");

    // --------------------------------------------------
    // Alice writes a record at the maximum size.
    // --------------------------------------------------
    let mut data = [0u8; 1000];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let max_size = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, max_size, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should fail authorization if protocol message size is greater than specified
// maximum size.
#[tokio::test]
async fn protocol_max_size() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a custom protocol with data size rules.
    // --------------------------------------------------
    let definition = Definition::new("http://blob-size.xyz")
        .published(true)
        .add_type("blob", ProtocolType::default())
        .add_rule("blob", RuleSet {
            size: Some(Range {
                min: None,
                max: Some(1000),
            }),
            ..RuleSet::default()
        });

    let configure = ConfigureBuilder::new()
        .definition(definition)
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record above the minimum size.
    // --------------------------------------------------
    let mut data = [0u8; 1001];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let too_big = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, too_big, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "data size is greater than allowed");

    // --------------------------------------------------
    // Alice writes a record at the maximum size.
    // --------------------------------------------------
    let mut data = [0u8; 1000];
    rand::thread_rng().fill_bytes(&mut data);
    let stream = DataStream::from(data.to_vec());

    let max_size = WriteBuilder::new()
        .data(Data::Stream(stream))
        .protocol(ProtocolBuilder {
            protocol: "http://blob-size.xyz",
            protocol_path: "blob",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, max_size, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should fail when write references a parent that has been deleted.
#[tokio::test]
async fn deleted_parent() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a nested protocol: foo -> bar -> baz.
    // --------------------------------------------------
    let nested = include_bytes!("../crates/dwn-test/protocols/nested.json");
    let definition: Definition = serde_json::from_slice(nested).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes foo1.
    // --------------------------------------------------
    let foo1 = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .schema("foo")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, foo1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes foo1.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&foo1.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");
    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should delete");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to write bar1 under foo1.
    // --------------------------------------------------
    let bar1 = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar",
            parent_context_id: foo1.context_id,
        })
        .schema("bar")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bar1, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find parent record");
}

// Should fail when write references a different parent to the one specified
// in `context_id`.
#[tokio::test]
async fn incorrect_parent_context() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a nested protocol: foo -> bar -> baz.
    // --------------------------------------------------
    let nested = include_bytes!("../crates/dwn-test/protocols/nested.json");
    let definition: Definition = serde_json::from_slice(nested).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes foo1.
    // --------------------------------------------------
    let foo1 = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .schema("foo")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, foo1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts (and fails) to write bar1 using an invalid context_id.
    // --------------------------------------------------
    let mut bar1 = WriteBuilder::new()
        .data(Data::from(b"some request".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar",
            parent_context_id: foo1.context_id,
        })
        .schema("bar")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    bar1.context_id = Some(format!("differentParent/{}", bar1.record_id));
    bar1.record_id = bar1.entry_id(ALICE_DID).expect("should create record ID");
    bar1.sign_as_author(None, None, &alice_keyring).await.expect("should sign");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bar1, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "incorrect parent `context_id`");
}

// Should allow writes when protocol and grant scope matches.
#[tokio::test]
async fn protocol_grant_match() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record using the grant.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should prevents writes when protocol and grant scope do not match.
#[tokio::test]
async fn protocol_grant_mismatch() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures 2 protocols.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records using the email protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://email-protocol.xyz".to_string(),
            limited_to: None,
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record using the grant and theminimal protocol.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_write, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "scope protocol does not match write protocol");
}

// Should allow writes when protocol and context grant scope match.
#[tokio::test]
async fn protocol_context_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates the context that she will give Bob access to.
    // --------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"data1".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records using the email protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://email-protocol.xyz".to_string(),
            limited_to: Some(RecordsScope::ContextId(alice_write.context_id.clone().unwrap())),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to write a record to the protocol.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email/email",
            parent_context_id: alice_write.context_id,
        })
        .schema("email")
        .data_format("text/plain")
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should prevent writes when protocol and context grant scope do not match.
#[tokio::test]
async fn protocol_context_no_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates the context that she will give Bob access to.
    // --------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"data1".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records using the email protocol.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://email-protocol.xyz".to_string(),
            limited_to: Some(RecordsScope::ContextId("nonexistentparentid".to_string())),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to write a record to the protocol.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email/email",
            parent_context_id: alice_write.context_id,
        })
        .schema("email")
        .data_format("text/plain")
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_write, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "record not part of grant context");
}

// Should allow writes when protocol and protocol path grant scope match.
#[tokio::test]
async fn protocol_path_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ProtocolPath("foo".to_string())),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to write a record to the protocol.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_write, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should prevent writes when protocol and protocol path grant scope do not match.
#[tokio::test]
async fn protocol_path_no_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ProtocolPath("some-other-path".to_string())),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses the grant to write a record to the protocol.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, bob_write, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant and record protocol paths do not match");
}

// Should prevent creation of unpublished records when grant requires they be
// published.
#[tokio::test]
async fn grant_publish_required() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .conditions(Conditions {
            publication: Some(Publication::Required),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob is able to create a published record .
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(&bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, published, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create an unpublished record .
    // --------------------------------------------------
    let unpublished = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, unpublished, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant requires message to be published");
}

// Should prevent creation of unpublished records when grant requires they be
// published.
#[tokio::test]
async fn grant_publish_prohibited() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .conditions(Conditions {
            publication: Some(Publication::Prohibited),
        })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob is able to create an unpublished record .
    // --------------------------------------------------
    let unpublished = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(&bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, unpublished, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create a published record .
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, published, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant prohibits publishing message");
}

// Should allow creation of both published and unpublished records when grant
// does not specify.
#[tokio::test]
async fn grant_publish_undefined() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../crates/dwn-test/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(BOB_DID)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .conditions(Conditions { publication: None })
        .build(&alice_keyring)
        .await
        .expect("should create grant");
    let reply =
        endpoint::handle(ALICE_DID, bob_grant.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob is able to create an unpublished record .
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(&bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, published, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts (and fails) to create a published record .
    // --------------------------------------------------
    let unpublished = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .permission_grant_id(bob_grant.record_id)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, unpublished, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should prevent writes where neither data stream nor data CID are provided.
#[tokio::test]
async fn missing_data_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record without a data stream.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);

    let initial = WriteBuilder::new()
        .data(Data::Bytes(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Update the record, still without a data stream.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::Bytes(data.to_vec()))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "referenced data does not exist");
}

// Should prevent writes where neither data stream nor encoded data are provided.
#[tokio::test]
async fn missing_encoded_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record without a data stream.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);

    let initial = WriteBuilder::new()
        .data(Data::Bytes(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Update the record, still without a data stream.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::Bytes(data.to_vec()))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "referenced data does not exist");
}

// Should prevent updates to a record after it has been deleted.
#[tokio::test]
async fn write_after_delete() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let initial = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&initial.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");
    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should delete");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record, still without a data stream.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "record has been deleted");
}

// Should prevent referencing data across web nodes.
#[tokio::test]
async fn cross_tenant_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record to her web node.
    // --------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice verifies her record has encoded data.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&alice_write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, query.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(b"some data")));

    // --------------------------------------------------
    // Bob learns the `data_cid` of Alice's record and attempts to gain
    // access by referencing it in his own web node.
    // --------------------------------------------------
    let bob_write = WriteBuilder::new()
        .data(Data::Cid {
            data_cid: alice_write.descriptor.data_cid,
            data_size: alice_write.descriptor.data_size,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, bob_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Bob attempts (and fails) to read his record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&bob_write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(BOB_DID, query.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());
}

// Should fail when `record_id` does not match signature `record_id`.
#[tokio::test]
async fn record_id_mismatch() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice attempts (and fails) to write a record with an altered `record_id`.
    // --------------------------------------------------
    let mut write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the record ID
    write.record_id = "somerandomrecordid".to_string();

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "message and authorization record IDs do not match");
}

// Should fail when `context_id` does not match signature `context_id`.
#[tokio::test]
async fn context_id_mismatch() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice attempts (and fails) to write a record with an altered `context_id`.
    // --------------------------------------------------
    let mut write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the signature context ID
    let payload = SignaturePayload {
        base: JwsPayload {
            descriptor_cid: data::cid::from_value(&write.descriptor).unwrap(),
            ..JwsPayload::default()
        },
        record_id: write.record_id.clone(),
        context_id: Some("somerandomrecordid".to_string()),
        ..SignaturePayload::default()
    };
    write.authorization.signature = JwsBuilder::new()
        .payload(payload)
        .add_signer(&alice_keyring)
        .build()
        .await
        .expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "message and authorization context IDs do not match");
}

// Should fail when if `attestation` payload contains properties other than
// `descriptor_cid`.
#[tokio::test]
async fn invalid_attestation() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice attempts (and fails) to write a record with an altered `attestation_cid`.
    // --------------------------------------------------
    let mut write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the signature attestation CID
    let payload = SignaturePayload {
        base: JwsPayload {
            descriptor_cid: data::cid::from_value(&write.descriptor).unwrap(),
            ..JwsPayload::default()
        },
        record_id: write.record_id.clone(),
        context_id: write.context_id.clone(),
        attestation_cid: Some("somerandomrecordid".to_string()),
        ..SignaturePayload::default()
    };
    write.authorization.signature = JwsBuilder::new()
        .payload(payload)
        .add_signer(&alice_keyring)
        .build()
        .await
        .expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "message and authorization attestation CIDs do not match");
}

// TODO: Should fail validation when more than 1 attester is given.
#[tokio::test]
#[ignore]
async fn multiple_attesters() {
    // TODO: add support for multiple attesters
}

// Should fail validation when attestation does not include the correct
// `descriptor_cid`.
#[tokio::test]
async fn attestation_descriptor_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice attempts (and fails) to write a record with an altered attestation
    // `descriptor_cid`.
    // --------------------------------------------------
    let mut write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // alter the attestation descriptor_cid
    let payload = Attestation {
        descriptor_cid: data::cid::from_value(&"somerandomrecordid").expect("should create CID"),
    };
    let attestation = JwsBuilder::new()
        .payload(payload)
        .add_signer(&alice_keyring)
        .build()
        .await
        .expect("should sign");

    let payload = SignaturePayload {
        base: JwsPayload {
            descriptor_cid: data::cid::from_value(&write.descriptor).unwrap(),
            ..JwsPayload::default()
        },
        record_id: write.record_id.clone(),
        context_id: write.context_id.clone(),
        attestation_cid: Some(data::cid::from_value(&attestation).unwrap()),
        ..SignaturePayload::default()
    };
    write.authorization.signature = JwsBuilder::new()
        .payload(payload)
        .add_signer(&alice_keyring)
        .build()
        .await
        .expect("should sign");

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "message and authorization attestation CIDs do not match");
}

// TODO: Should fail when an unknown error is returned.
#[tokio::test]
#[ignore]
async fn unknown_error() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record without data.
    // --------------------------------------------------
    let initial =
        WriteBuilder::new().sign(&alice_keyring).build().await.expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Update the record, providing data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial.clone())
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, update.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // simulate throwing unexpected error
}
