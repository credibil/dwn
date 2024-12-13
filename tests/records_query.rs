//! Messages Subscribe

use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use rand::RngCore;
use vercre_dwn::data::{DataStream, MAX_ENCODED_SIZE};
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{
    QueryBuilder, RecordsFilter, Sort, Write, WriteBuilder, WriteData, WriteProtocol,
};
use vercre_dwn::{Error, authorization, endpoint};

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
async fn find_matches() {
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
async fn attester_filter() {
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
async fn author_filter() {
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

// Should query by recipient.
#[tokio::test]
async fn recipient_filter() {
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
    // Alice creates 2 records.
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
async fn published_filter() {
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
async fn unpublished_filter() {
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

    // // --------------------------------------------------
    // // Alice publishes the unpublished record.
    // // --------------------------------------------------
    // let published = WriteBuilder::from(unpublished)
    //     .published(true)
    //     .sign(&alice_keyring)
    //     .build()
    //     .await
    //     .expect("should create write");
    // let reply =
    //     endpoint::handle(ALICE_DID, published.clone(), &provider).await.expect("should write");
    // assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // // --------------------------------------------------
    // // Alice (owner) queries for published record.
    // // --------------------------------------------------
    // let query = QueryBuilder::new()
    //     .filter(RecordsFilter::new().schema("post").published(true))
    //     .sign(&alice_keyring)
    //     .build()
    //     .await
    //     .expect("should create query");
    // let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should query");
    // assert_eq!(reply.status.code, StatusCode::OK);

    // let query_reply = reply.body.expect("should have reply");
    // let entries = query_reply.entries.expect("should have entries");
    // assert_eq!(entries.len(), 1);
    // assert_eq!(entries[0].write.record_id, published.record_id);
}
