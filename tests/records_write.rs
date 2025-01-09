//! Records Write

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use dwn_test::key_store::{ALICE_DID, APP_DID as VC_ISSUER_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::messages::{self, MessagesFilter};
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::{EventLog, KeyStore};
use vercre_dwn::records::{
    Data, QueryBuilder, ReadBuilder, RecordsFilter, WriteBuilder, WriteProtocol, entry_id,
};
use vercre_dwn::store::MessagesQuery;
use vercre_dwn::{Error, Interface, Message, endpoint};

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

// Should allow an initial write without data.
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

// Should not allow a record to be updated without data.
#[tokio::test]
async fn update_no_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record with no data.
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
    // Update the record, adding data.
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
    assert_eq!(e, "actual data CID does not match message `data_cid`");

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
    write.record_id = entry_id(&write.descriptor, ALICE_DID).expect("should create record ID");

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
    write.record_id = entry_id(&write.descriptor, ALICE_DID).expect("should create record ID");

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
    write.record_id = entry_id(&write.descriptor, ALICE_DID).expect("should create record ID");

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

    // alter the data size and recalculate the `record_id`
    write.descriptor.data_size = 1;
    write.record_id = entry_id(&write.descriptor, ALICE_DID).expect("should create record ID");

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

// Should prevent accessing data by referencing a different`data_cid` in an update.
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
        .data(Data::Stream(DataStream::from(data_1.to_vec())))
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
        .data(Data::Stream(DataStream::from(data_2.to_vec())))
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
        .data(Data::Stream(DataStream::from(data_1.to_vec())))
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
        .data(Data::Stream(DataStream::from(data_2.to_vec())))
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
        .protocol(WriteProtocol {
            protocol: "http://email-protocol.xyz".to_string(),
            protocol_path: "email".to_string(),
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
    assert_eq!(e, "invalid `context_id`");
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
    let email_data = b"Hello Alice";
    let email = WriteBuilder::new()
        .data(Data::Stream(DataStream::from(email_data.to_vec())))
        .protocol(WriteProtocol {
            protocol: "http://email-protocol.xyz".to_string(),
            protocol_path: "email".to_string(),
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
    assert_eq!(entries[0].write.encoded_data, Some(Base64UrlUnpadded::encode_string(email_data)));
}

// Should allow anyone to create a record using the "anyone co-update" rule.
#[tokio::test]
async fn anyone_co_update() {
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
        .data(Data::Stream(DataStream::from(b"A document".to_vec())))
        .protocol(WriteProtocol {
            protocol: "http://anyone-collaborate-protocol.xyz".to_string(),
            protocol_path: "doc".to_string(),
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
        .data(Data::Stream(DataStream::from(b"An update".to_vec())))
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
        .data(Data::Stream(DataStream::from(b"A document".to_vec())))
        .protocol(WriteProtocol {
            protocol: "http://anyone-collaborate-protocol.xyz".to_string(),
            protocol_path: "doc".to_string(),
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
async fn allow_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let vc_issuer_keyring =
        provider.keyring(VC_ISSUER_DID).expect("should get VC issuer's keyring");

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../crates/dwn-test/protocols/credential-issuance.json");
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
    // Alice writes a credential application to her web node to simulate a
    // credential application being sent to a VC issuer.
    // --------------------------------------------------
    let application = WriteBuilder::new()
        .data(Data::Stream(DataStream::from(b"credential application data".to_vec())))
        .recipient(VC_ISSUER_DID)
        .protocol(WriteProtocol {
            protocol: "http://credential-issuance-protocol.xyz".to_string(),
            protocol_path: "credentialApplication".to_string(),
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
        .data(Data::Stream(DataStream::from(b"credential response data".to_vec())))
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://credential-issuance-protocol.xyz".to_string(),
            protocol_path: "credentialApplication/credentialResponse".to_string(),
        })
        .parent_context_id(application.context_id.unwrap())
        .schema("https://identity.foundation/credential-manifest/schemas/credential-response")
        .data_format("application/json")
        .sign(&vc_issuer_keyring)
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
