//! Records Write

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{Data, QueryBuilder, ReadBuilder, RecordsFilter, WriteBuilder, entry_id};
use vercre_dwn::{Error, Message, endpoint};

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
    let encoded_data = Base64UrlUnpadded::encode_string(data);

    let initial_write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify the record was created.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.encoded_data, Some(encoded_data));

    // --------------------------------------------------
    // Update the existing record.
    // --------------------------------------------------
    let data = b"updated write record";
    let encoded_data = Base64UrlUnpadded::encode_string(data);

    let update = WriteBuilder::from(initial_write.clone())
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
    assert_eq!(entries[0].write.encoded_data, Some(encoded_data.clone()));

    // --------------------------------------------------
    // Attempt to overwrite the latest record with an older version.
    // --------------------------------------------------
    let Err(Error::Conflict(e)) = endpoint::handle(ALICE_DID, initial_write, &provider).await
    else {
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
    assert_eq!(entries[0].write.encoded_data, Some(encoded_data));
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"a new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Create 2 records with the same `message_timestamp`.
    // --------------------------------------------------
    // let message_timestamp = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();
    let message_timestamp = initial_write.descriptor.base.message_timestamp + Duration::seconds(1);

    let write_1 = WriteBuilder::from(initial_write.clone())
        .data(Data::from(b"message 1".to_vec()))
        .message_timestamp(message_timestamp.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let write_2 = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"a new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record with a new data format.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let date_created = Utc::now();

    let update = WriteBuilder::new()
        .record_id(initial_write.record_id.clone())
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
        .record_id(initial_write.record_id.clone())
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
    let initial_write =
        WriteBuilder::new().sign(&alice_keyring).build().await.expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::NO_CONTENT);

    // --------------------------------------------------
    // Verify the record cannot be queried for.
    // --------------------------------------------------
    let read = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record, adding data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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

    let initial_write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record but not data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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

    let initial_write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Update the record but not data.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
    let initial_write = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, initial_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Verify `date_created` cannot be updated.
    // --------------------------------------------------
    let update = WriteBuilder::from(initial_write.clone())
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
        .filter(RecordsFilter::new().record_id(&initial_write.record_id))
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
        initial_write.descriptor.date_published.unwrap().timestamp_micros()
    );
}

// Should fail when updating a record but its initial write cannot be found.
#[tokio::test]
async fn no_initial_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let update = WriteBuilder::new()
        .data(Data::from(b"new write record".to_vec()))
        .record_id("bafkreihs5gnovjoqueffglvevvohpgts3aj5ykgmlqm7quuotujxtxtp7f")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "initial write not found");
}

// Should fail when creating a record if `date_created` and `message_timestamp`
// are not the same.
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
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, initial.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "`message_timestamp` and `date_created` do not match");
}
