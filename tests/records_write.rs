//! Records Write

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc}; //DateTime,
use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE, cid};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{Data, QueryBuilder, ReadBuilder, RecordsFilter, WriteBuilder};
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
    let data = br#"a new write record"#;
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
    let data = br#"updated write record"#;
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
        .data(Data::from(br#"a new write record"#.to_vec()))
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
        .data(Data::from(br#"message 1"#.to_vec()))
        .message_timestamp(message_timestamp.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let write_2 = WriteBuilder::from(initial_write.clone())
        .data(Data::from(br#"message 2"#.to_vec()))
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
        .data(Data::from(br#"a new write record"#.to_vec()))
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
        .data(Data::from(br#"update write record"#.to_vec()))
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

// Should not allow changes to immutable properties.
#[tokio::test]
async fn immutable_unchanged() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Write a record.
    // --------------------------------------------------
    let initial_write = WriteBuilder::new()
        .data(Data::from(br#"new write record"#.to_vec()))
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
        .data(Data::from(br#"update write record"#.to_vec()))
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
        .data(Data::Bytes(br#"update write record"#.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, update.clone(), &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "computed data CID does not match message `data_cid`");

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

    // change the data size
    write.descriptor.data_size = MAX_ENCODED_SIZE + 100;
    // write.descriptor.data_cid = cid::from_value(&write).expect("should create CID");
    // write.record_id=entry_id();

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

    // change the data size
    write.descriptor.data_size = MAX_ENCODED_SIZE + 100;

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

    // change the data size
    write.descriptor.data_size = 1;
    // write.descriptor.data_cid = cid::from_value(&write).expect("should create CID");
    // write.record_id=entry_id();

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

    // change the data size
    write.descriptor.data_size = 1;

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, write, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "actual data size does not match message `data_size`");
}
