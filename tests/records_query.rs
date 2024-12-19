//! Messages Subscribe

use chrono::{DateTime, Duration};
use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{
    DateRange, QueryBuilder, RecordsFilter, Sort, Write, WriteBuilder, WriteData, WriteProtocol,
};
use vercre_dwn::store::Pagination;
use vercre_dwn::{Error, Message, RangeFilter, authorization, endpoint};

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
async fn response() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates a record.
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
async fn matches() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records.
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
    // Alice creates a record.
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
    // Alice creates a record.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);

    let write = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
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

// Should return `initial_write` when RecordsWrite is not initial write.
#[tokio::test]
async fn initial_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 2 records.
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

    // update existing record
    let write =
        WriteBuilder::from(write).sign(&alice_keyring).build().await.expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `initial_write` in reply.
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
    assert!(entry.initial_write.is_some());
}

// Should be able to query by attester.
#[tokio::test]
async fn attester() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 2 records, 1 attested by her and the other by Bob.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .attest(&[&alice_keyring])
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .schema("schema_2")
        .attest(&[&bob_keyring])
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Query by attester.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(ALICE_DID))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];

    let attester = authorization::signer_did(&entry.write.attestation.as_ref().unwrap()).unwrap();
    assert_eq!(attester, ALICE_DID);

    // --------------------------------------------------
    // Query by another attester + schema.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(BOB_DID).schema("schema_2"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];

    let attester = authorization::signer_did(&entry.write.attestation.as_ref().unwrap()).unwrap();
    assert_eq!(attester, BOB_DID);

    // --------------------------------------------------
    // Check that 3rd attester will return no results.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(CAROL_DID))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());
}

// Should be able to query by author.
#[tokio::test]
async fn author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice and Bob write a record each.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());
    let alice_write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_write = Write::build()
        .data(WriteData::Reader(stream.clone()))
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, bob_write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for all records within the protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
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
    // Alice queries for Bob's records within the protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_author(BOB_DID)
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, bob_write.record_id);

    // --------------------------------------------------
    // Alice queries both author's records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_author(ALICE_DID)
                .add_author(BOB_DID)
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should allow web node owner to query by recipient.
#[tokio::test]
async fn owner_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records, 1 for Bob and 1 for Carol.
    // --------------------------------------------------
    let alice_bob = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_bob.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_carol = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_carol.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for all records within the protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
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
    // Alice queries for record where Bob is the recipient.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(BOB_DID)
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, alice_bob.record_id);

    // --------------------------------------------------
    // Alice queries for record where Carol is the recipient.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(CAROL_DID)
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, alice_carol.record_id);

    // --------------------------------------------------
    // Alice queries both recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(BOB_DID)
                .add_recipient(CAROL_DID)
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should query for published records.
#[tokio::test]
async fn published() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 2 records: 1 published and 1 unpublished.
    // --------------------------------------------------
    let published = Write::build()
        .schema("post")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let unpublished = Write::build()
        .schema("post")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, unpublished.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice (owner) queries for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);

    // --------------------------------------------------
    // Bob (not owner) queries for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);

    // --------------------------------------------------
    // Anonymous query for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .build()
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);

    // --------------------------------------------------
    // Alice publishes the unpublished record.
    // --------------------------------------------------
    let published = WriteBuilder::from(unpublished)
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice (owner) queries for published records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
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
    // Anonymous query for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .build()
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should not be able to query for unpublished records when not authorized.
#[tokio::test]
async fn unpublished() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 2 records: 1 published and 1 unpublished.
    // --------------------------------------------------
    let published = Write::build()
        .schema("post")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let unpublished = Write::build()
        .schema("post")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, unpublished.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the unpublished record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Bob unsuccessfully queries for unpublished record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    assert!(reply.body.is_none());

    // --------------------------------------------------
    // Alice publishes the unpublished record.
    // --------------------------------------------------
    let published = WriteBuilder::from(unpublished)
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries without setting `published` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post"))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Bob queries using the `published` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice unsuccessfully queries for unpublished records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    assert!(reply.body.is_none());
}

// Should be able to query for a record by data_cid.
#[tokio::test]
async fn data_cid() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let stream = DataStream::from(br#"{"message": "test record write"}"#.to_vec());

    let write = Write::build()
        .data(WriteData::Reader(stream))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries using the `data_cid` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_cid(write.descriptor.data_cid))
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

// Should be able to query for a record by data_size (half-open range).
#[tokio::test]
async fn dat_size_part_range() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying data sizes.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);

    let write10 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write10.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let mut data = [0u8; 50];
    rand::thread_rng().fill_bytes(&mut data);

    let write50 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write50.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let mut data = [0u8; 100];
    rand::thread_rng().fill_bytes(&mut data);

    let write100 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write100.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Greater than 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().gt(10)))
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
    // Less than 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().lt(100)))
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
    // Greater than or equal to 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().ge(10)))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // --------------------------------------------------
    // Less than or equal to 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().le(100)))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should be able to query for a record by data_size (open or closed range).
#[tokio::test]
async fn data_size_full_range() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying data sizes.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut data);

    let write10 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write10.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let mut data = [0u8; 50];
    rand::thread_rng().fill_bytes(&mut data);

    let write50 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write50.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let mut data = [0u8; 100];
    rand::thread_rng().fill_bytes(&mut data);

    let write100 = Write::build()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write100.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Greater than 10, less than 60.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().gt(10).lt(60)))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Greater than or equal to 10, less than 60.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().ge(10).lt(60)))
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
    // Greater than 50, less than or equal to 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().gt(50).le(100)))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Greater than or equal to 10, less than or equal to 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(RangeFilter::new().ge(10).le(100)))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should be able to query for records where date_created is within a specfied range.
#[tokio::test]
async fn date_created_range() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = Write::build()
        .date_created(first_2022.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = Write::build()
        .date_created(first_2023.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = Write::build()
        .date_created(first_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
    assert_eq!(entries[1].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // To (less than).
    // --------------------------------------------------
    let last_2023 = DateTime::parse_from_rfc3339("2023-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().lt(last_2023.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2022.record_id);
    assert_eq!(entries[1].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // From and To (between).
    // --------------------------------------------------
    let last_2024 = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_created(DateRange::new().gt(last_2023.into()).lt(last_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // Edge case where value equals `from` and `to`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_created(DateRange::new().gt(first_2023.into()).lt(first_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should not return records that were published and then unpublished.
#[tokio::test]
async fn published_unpublished() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = Write::build()
        .date_created(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = Write::build()
        .date_created(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = Write::build()
        .date_created(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Confirm range before unpublishing.
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Confirm published before unpublishing.
    // --------------------------------------------------
    // owner-requested date range
    let owner_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply =
        endpoint::handle(ALICE_DID, owner_range.clone(), &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    // owner-requested date range
    let owner_published = QueryBuilder::new()
        .filter(RecordsFilter::new().published(true))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, owner_published.clone(), &provider)
        .await
        .expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // anonymous request date range
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .build()
        .expect("should create query");
    let reply =
        endpoint::handle(ALICE_DID, anon_range.clone(), &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // anonymous `published` filter
    let anon_published = QueryBuilder::new()
        .filter(RecordsFilter::new().published(true))
        .date_sort(Sort::CreatedAscending)
        .build()
        .expect("should create query");
    let reply =
        endpoint::handle(ALICE_DID, anon_range.clone(), &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Confirm published before unpublishing.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().published(true))
        .build()
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // --------------------------------------------------
    // Unpublish.
    // --------------------------------------------------
    let unwrite_2022 = WriteBuilder::from(write_2022)
        .published(false)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply =
        endpoint::handle(ALICE_DID, unwrite_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let unwrite_2023 = WriteBuilder::from(write_2023)
        .published(false)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, unwrite_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let unwrite_2024 = WriteBuilder::from(write_2024)
        .published(false)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, unwrite_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Earlier anonymous requests should return no results.
    // --------------------------------------------------
    // published date range filter
    let reply = endpoint::handle(ALICE_DID, anon_range, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // published 'true' filter
    let reply = endpoint::handle(ALICE_DID, anon_published, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // --------------------------------------------------
    // Earlier anonymous requests should return no results.
    // --------------------------------------------------
    // published date range filter
    let reply = endpoint::handle(ALICE_DID, owner_range, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // published 'true' filter
    let reply =
        endpoint::handle(ALICE_DID, owner_published, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());
}

// Should be able to query by date published.
#[tokio::test]
async fn date_published() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = Write::build()
        .date_created(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = Write::build()
        .date_created(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = Write::build()
        .date_created(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
    assert_eq!(entries[1].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // To (less than).
    // --------------------------------------------------
    let last_2023 = DateTime::parse_from_rfc3339("2023-12-31T00:00:00-00:00").unwrap();
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().lt(last_2023.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2022.record_id);
    assert_eq!(entries[1].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // From and To (between).
    // --------------------------------------------------
    let last_2024 = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_published(DateRange::new().gt(last_2023.into()).lt(last_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // Edge case where value equals `from` and `to`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_published(DateRange::new().gt(first_2023.into()).lt(first_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Anonymous request should return  results.
    // --------------------------------------------------
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .build()
        .expect("should create query");
    let reply =
        endpoint::handle(ALICE_DID, anon_range.clone(), &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Non-owner request should return  results.
    // --------------------------------------------------
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply =
        endpoint::handle(ALICE_DID, anon_range.clone(), &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should be able to query by date updated.
#[tokio::test]
async fn date_updated() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2021 = DateTime::parse_from_rfc3339("2021-01-01T00:00:00-00:00").unwrap();

    let write_1 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_1".to_vec())))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_2".to_vec())))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_3 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_3".to_vec())))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_3.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Publish records (thereby updating them)
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();

    let write_2022 = WriteBuilder::from(write_1)
        .message_timestamp(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2023 = WriteBuilder::from(write_2)
        .message_timestamp(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2024 = WriteBuilder::from(write_3)
        .message_timestamp(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();
    let last_2023 = DateTime::parse_from_rfc3339("2023-12-31T00:00:00-00:00").unwrap();
    let last_2024 = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_updated(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
    assert_eq!(entries[1].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // To (less than).
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_updated(DateRange::new().lt(last_2023.into())))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2022.record_id);
    assert_eq!(entries[1].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // From and To (between).
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_updated(DateRange::new().gt(last_2023.into()).lt(last_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2024.record_id);

    // --------------------------------------------------
    // Edge case where value equals `from` and `to`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .date_updated(DateRange::new().gt(first_2023.into()).lt(first_2024.into())),
        )
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should be able use range and exact match queries together.
#[tokio::test]
async fn range_and_match() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = Write::build()
        .date_created(first_2022.into())
        .schema("2022And2023Schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2022.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = Write::build()
        .date_created(first_2023.into())
        .schema("2022And2023Schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2023.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = Write::build()
        .date_created(first_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2024.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Range and match.
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();
    let last_2024 = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .schema("2022And2023Schema")
                .date_created(DateRange::new().gt(last_2022.into()).lt(last_2024.into())),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should include `authorization` in returned records.
#[tokio::test]
async fn authorization() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let write = Write::build()
        .schema("schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the record, expecting to find `authorization` property.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    assert_snapshot!("authorization", entries[0].write.authorization, {
        ".signature.payload" => "[payload]",
        ".signature.signatures[0].signature" => "[signature]",
        // ".attestation.payload" => "[payload]",
        // ".attestation.signatures[0].signature" => "[signature]",
    });
}

// Should include `attestation` in returned records.
#[tokio::test]
async fn attestation() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let write = Write::build()
        .schema("schema")
        .attest(&[&alice_keyring])
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the record, expecting to find `authorization` property.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    assert_snapshot!("attestation", entries[0].write.attestation, {
        ".payload" => "[payload]",
        ".signatures[0].signature" => "[signature]",
    });
}

// Should exclude unpublished records when sorting on `date_published`.
#[tokio::test]
async fn exclude_unpublished() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 2 records, 1 published the other unpublished.
    // --------------------------------------------------
    let published = Write::build()
        .schema("schema")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should) create write");
    let reply =
        endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let unpublished = Write::build()
        .schema("schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, unpublished.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Sorting by `date_published` should not include unpublished records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);
}

// Should sort records if `date_sort` is specified (with and without a cursor).
#[tokio::test]
async fn date_sort() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records.
    // --------------------------------------------------
    let ts_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let ts_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let ts_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();

    let write_1 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_1".to_vec())))
        .schema("schema")
        .published(true)
        .date_created(ts_2022.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_2".to_vec())))
        .schema("schema")
        .published(true)
        .date_created(ts_2023.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_3 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_3".to_vec())))
        .schema("schema")
        .published(true)
        .date_created(ts_2024.into())
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_3.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // CreatedAscending: sort
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedAscending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAscending)
        .pagination(Pagination::new().limit(1))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);

    // --------------------------------------------------
    // CreatedAscending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAscending)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDescending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_3.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDescending)
        .pagination(Pagination::new().limit(1))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_3.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDescending)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAscending)
        .pagination(Pagination::new().limit(1))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAscending)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDescending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_3.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDescending)
        .pagination(Pagination::new().limit(1))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_3.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDescending)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);
}

// FIXME: we need to sort by cid in records query
// Should tiebreak using `message_cid` when sorting identical values.
#[tokio::test]
async fn sort_identical() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 3 records.
    // --------------------------------------------------
    let timestamp = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let write_1 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_1".to_vec())))
        .date_created(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let write_2 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_2".to_vec())))
        .date_created(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let write_3 = Write::build()
        .data(WriteData::Reader(DataStream::from(b"write_3".to_vec())))
        .date_created(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    // reverse sort newest to oldest by message_cid
    let mut sorted_write = vec![write_1.clone(), write_2.clone(), write_3.clone()];
    sorted_write.sort_by(|a, b| b.cid().unwrap().cmp(&a.cid().unwrap()));

    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
    let reply =
        endpoint::handle(ALICE_DID, write_3.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // CreatedAscending: verify messages returned are sorted by `message_cid`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAscending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.cid().unwrap(), sorted_write[2].cid().unwrap());
    assert_eq!(entries[1].write.record_id, sorted_write[1].record_id);

    // --------------------------------------------------
    // CreatedDescending: verify messages returned are sorted by `message_cid`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDescending)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, sorted_write[0].record_id);
    assert_eq!(entries[1].write.record_id, sorted_write[1].record_id);
}

// Should paginate all records in ascending order.
#[tokio::test]
async fn paginate_ascending() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 12 records.
    // --------------------------------------------------
    let mut writes = vec![];
    let mut date_created = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    for i in 0..12 {
        date_created -= Duration::days(1);

        let write = Write::build()
            .date_created(date_created.into())
            .data(WriteData::Reader(DataStream::from(format!("write_{}", i).into_bytes())))
            .schema("schema")
            .published(true)
            .sign(&alice_keyring)
            .build()
            .await
            .expect("should create write");
        let reply =
            endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
        writes.push(write);
    }

    // --------------------------------------------------
    // CreatedAscending: sort with pagination.
    // --------------------------------------------------
    let mut all_entries = vec![];
    let mut cursor = None;

    loop {
        let query = QueryBuilder::new()
            .filter(RecordsFilter::new().schema("schema"))
            .date_sort(Sort::CreatedAscending)
            .pagination(Pagination {
                limit: Some(5),
                cursor,
            })
            .sign(&alice_keyring)
            .build()
            .await
            .expect("should create query");
        let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
        assert_eq!(reply.status.code, StatusCode::OK);

        let query_reply = reply.body.expect("should have reply");
        let entries = query_reply.entries.expect("should have entries");

        all_entries.extend(entries.clone());
        cursor = query_reply.cursor;
        if cursor.is_none() {
            break;
        }
    }

    // all entries should be returned in correct order (opposite of created order)
    assert_eq!(all_entries.len(), 12);
    for i in (0..12).rev() {
        assert_eq!(all_entries[i].write.record_id, writes[11 - i].record_id);
    }
}

// Should paginate all records in descending order.
#[tokio::test]
async fn paginate_descending() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice creates 12 records.
    // --------------------------------------------------
    let mut writes = vec![];
    let mut date_created = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    for i in 0..12 {
        date_created += Duration::days(1);

        let write = Write::build()
            .data(WriteData::Reader(DataStream::from(format!("write_{}", i).into_bytes())))
            .schema("schema")
            .published(true)
            .date_created(date_created.into())
            .sign(&alice_keyring)
            .build()
            .await
            .expect("should create write");
        let reply =
            endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
        assert_eq!(reply.status.code, StatusCode::ACCEPTED);
        writes.push(write);
    }

    // --------------------------------------------------
    // PublishedDescending: sort with pagination.
    // --------------------------------------------------
    let mut all_entries = vec![];
    let mut cursor = None;

    loop {
        let query = QueryBuilder::new()
            .filter(RecordsFilter::new().schema("schema"))
            .date_sort(Sort::CreatedDescending)
            .pagination(Pagination {
                limit: Some(5),
                cursor,
            })
            .sign(&alice_keyring)
            .build()
            .await
            .expect("should create query");
        let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
        assert_eq!(reply.status.code, StatusCode::OK);

        let query_reply = reply.body.expect("should have reply");
        let entries = query_reply.entries.expect("should have entries");

        all_entries.extend(entries.clone());
        cursor = query_reply.cursor;
        if cursor.is_none() {
            break;
        }
    }

    // all entries should be returned in correct order (opposite of created order)
    assert_eq!(all_entries.len(), 12);
    for i in (0..12).rev() {
        assert_eq!(all_entries[i].write.record_id, writes[11 - i].record_id);
    }
}

// Should allow an anonymous query to return published records.
#[tokio::test]
async fn anonymous() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Create records.
    // --------------------------------------------------
    let write_1 = Write::build()
        .schema("http://schema1")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2 = Write::build()
        .schema("http://schema2")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Query anonymously.
    // --------------------------------------------------
    let early_date = DateTime::parse_from_rfc3339("2000-01-01T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(early_date.into())))
        .build()
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
}

// Should only return records meant for the specified recipient(s).
#[tokio::test]
async fn recipient_query() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records each for Bob and Carol; 2 public, 2 private.
    // --------------------------------------------------
    let alice_bob_private = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_bob_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_bob_public = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_bob_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_carol_private = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_carol_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_carol_public = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_carol_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol creates 2 records each for Alice and Bob; 2 public, 2 private.
    // --------------------------------------------------
    let carol_alice_private = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_alice_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_alice_public = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_alice_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_bob_private = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_bob_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_bob_public = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .published(true)
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_bob_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob creates 2 records each for Alice and Carol; 2 public, 2 private.
    // --------------------------------------------------
    let bob_alice_private = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_alice_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_alice_public = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_alice_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_carol_private = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_carol_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_carol_public = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_carol_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for messages with himself and Alice as recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_recipient(BOB_DID)
                .add_recipient(ALICE_DID),
        )
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Bob should be able to see 7 messages
    assert_eq!(entries.len(), 7);
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_public.record_id));

    // --------------------------------------------------
    // Carol queries for messages with herself as recipient.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_recipient(CAROL_DID),
        )
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 4 messages
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_public.record_id));

    // --------------------------------------------------
    // Alice queries for published records with herself and Bob as recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_recipient(ALICE_DID)
                .add_recipient(BOB_DID)
                .published(true),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 4 messages
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_public.record_id));

    // --------------------------------------------------
    // Carol queries for private messages with herself and Alice as recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_recipient(CAROL_DID)
                .add_recipient(ALICE_DID)
                .published(false),
        )
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 3 messages
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_private.record_id));
}

// Should only return records authored by the specified author(s).
#[tokio::test]
async fn author_query() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records each for Bob and Carol: 2 public, 2 private.
    // --------------------------------------------------
    let alice_bob_private = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_bob_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_bob_public = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_bob_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_carol_private = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_carol_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let alice_carol_public = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, alice_carol_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol creates 2 records each for Alice and Bob: 2 public, 2 private.
    // --------------------------------------------------
    let carol_alice_private = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_alice_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_alice_public = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_alice_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_bob_private = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_bob_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let carol_bob_public = Write::build()
        .recipient(BOB_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .published(true)
        .data_format("application/json")
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, carol_bob_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob creates 2 records each for Alice and Carol: 2 public, 2 private.
    // --------------------------------------------------
    let bob_alice_private = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_alice_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_alice_public = Write::build()
        .recipient(ALICE_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_alice_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_carol_private = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_carol_private.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let bob_carol_public = Write::build()
        .recipient(CAROL_DID)
        .protocol(WriteProtocol {
            protocol: "http://allow-any.xyz".to_string(),
            protocol_path: "post".to_string(),
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, bob_carol_public.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for messages with himself and Alice as authors.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_author(BOB_DID)
                .add_author(ALICE_DID),
        )
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Bob should be able to see 7 messages
    assert_eq!(entries.len(), 7);
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_public.record_id));

    // --------------------------------------------------
    // Carol queries for messages with herself as author.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_author(CAROL_DID),
        )
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 4 messages
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_public.record_id));

    // --------------------------------------------------
    // Alice queries for published records with herself and Bob as authors.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_author(ALICE_DID)
                .add_author(BOB_DID)
                .published(true),
        )
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 4 messages
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().any(|e| e.write.record_id == alice_bob_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_alice_public.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == bob_carol_public.record_id));

    // --------------------------------------------------
    // Carol queries for private messages with herself and Alice as recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_author(CAROL_DID)
                .add_author(ALICE_DID)
                .published(false),
        )
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 3 messages
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_private.record_id));
}
