//! Records Query

#![allow(clippy::too_many_lines)]
#![allow(clippy::large_stack_frames)]
#![allow(clippy::similar_names)]
#![cfg(all(feature = "client", feature = "server"))]
#![cfg(not(miri))] // waiting for https://github.com/rust-lang/miri/issues/602

use std::io::Cursor;

use chrono::{DateTime, Duration, Utc};
use credibil_dwn::api::Client;
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{
    Data, ProtocolBuilder, QueryBuilder, RecordsFilter, Sort, WriteBuilder,
};
use credibil_dwn::client::{DateRange, Pagination, Range};
use credibil_dwn::interfaces::records::QueryReply;
use credibil_dwn::store::MAX_ENCODED_SIZE;
use credibil_dwn::{Error, StatusCode, authorization};
use rand::RngCore;
use test_utils::{Identity, WebNode};
use tokio::sync::OnceCell;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static CAROL: OnceCell<Identity> = OnceCell::const_new();
static NODE: OnceCell<Client<WebNode>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("records_query_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("records_query_bob").await }).await
}
async fn carol() -> &'static Identity {
    CAROL.get_or_init(|| async { Identity::new("records_query_carol").await }).await
}
async fn node() -> &'static Client<WebNode> {
    NODE.get_or_init(|| async { Client::new(WebNode::new().await) }).await
}

// Should return a status of BadRequest (400) when querying for unpublished records
// with sort date set to `Sort::Publishedxxx`.
#[tokio::test]
async fn invalid_sort() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().published(false))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    query.descriptor.date_sort = Some(Sort::PublishedAsc);
    let Err(Error::BadRequest(e)) = node.request(query.clone()).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "cannot sort by `date_published` when querying for unpublished records");

    query.descriptor.date_sort = Some(Sort::PublishedDesc);
    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "cannot sort by `date_published` when querying for unpublished records");
}

// Should return `record_id`, `descriptor`, `authorization` and `attestation` fields.
#[tokio::test]
async fn response() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .data_format("awesome_data_format")
        .attest(&[bob])
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for records with matching format.
    // --------------------------------------------------
    let filter = RecordsFilter::new().add_author(alice.did()).data_format("awesome_data_format");
    let query =
        QueryBuilder::new().filter(filter).sign(alice).build().await.expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write.record_id);
}

// Should return matching records.
#[tokio::test]
async fn matches() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());

    for i in 1..=3 {
        let mut builder = WriteBuilder::new().data(Data::Stream(stream.clone()));

        if i > 1 {
            builder = builder.data_format("awesome_data_format").schema(format!("schema_{i}"));
        }

        let write = builder.sign(alice).build().await.expect("should create write");
        let reply = node.request(write).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice queries for records with matching format.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_format("awesome_data_format"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice queries for records with matching schema.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_format("awesome_data_format").schema("schema_2"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should return `encoded_data` if data size is within the spec threshold.
#[tokio::test]
async fn encoded_data() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `encoded_data`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];
    assert!(entry.write.encoded_data.is_some());
}

// Should return `encoded_data` if data size is within the spec threshold.
#[tokio::test]
async fn no_encoded_data() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    #[allow(clippy::large_stack_arrays)]
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::rng().fill_bytes(&mut data);

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `encoded_data`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];
    assert!(entry.write.encoded_data.is_none());
}

// Should return `initial_write` when RecordsWrite is not initial write.
#[tokio::test]
async fn initial_write() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 2 records.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // update existing record
    let write = WriteBuilder::from(write).sign(alice).build().await.expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for record, expecting to get `initial_write` in reply.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];
    assert!(entry.initial_write.is_some());
}

// Should be able to query by attester.
#[tokio::test]
async fn attester() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice creates 2 records, 1 attested by her and the other by BOB.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .attest(&[alice])
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .schema("schema_2")
        .attest(&[bob])
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Query by attester.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(alice.did()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];

    let attester = authorization::kid_did(entry.write.attestation.as_ref().unwrap())
        .expect("should have attester");
    assert_eq!(attester, alice.did(),);

    // --------------------------------------------------
    // Query by another attester + schema.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(bob.did()).schema("schema_2"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    let entry = &entries[0];

    let attester = authorization::kid_did(entry.write.attestation.as_ref().unwrap())
        .expect("should have attester");
    assert_eq!(attester, bob.did(),);

    // --------------------------------------------------
    // Check that 3rd attester will return no results.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().attester(carol.did()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());
}

// Should be able to query by author.
#[tokio::test]
async fn author() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice and Bob write a record each.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());
    let alice_write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_write = WriteBuilder::new()
        .data(Data::Stream(stream.clone()))
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bob_write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice queries for Bob's records within the protocol.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_author(bob.did())
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, bob_write.record_id);

    // --------------------------------------------------
    // Alice queries both author's records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_author(alice.did())
                .add_author(bob.did())
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should allow web node owner to query by recipient.
#[tokio::test]
async fn owner_recipient() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records, 1 for Bob and 1 for CAROL.
    // --------------------------------------------------
    let alice_bob = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_bob.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_carol = WriteBuilder::new()
        .data(Data::from(b"Hello Carol".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_carol.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice queries for record where Bob is the recipient.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(bob.did())
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, alice_bob.record_id);

    // --------------------------------------------------
    // Alice queries for record where Carol is the recipient.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(carol.did())
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, alice_carol.record_id);

    // --------------------------------------------------
    // Alice queries both recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .add_recipient(bob.did())
                .add_recipient(carol.did())
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .schema("post")
                .data_format("application/json"),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should query for published records.
#[tokio::test]
async fn published() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates 2 records: 1 published and 1 unpublished.
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"published".to_vec()))
        .schema("post")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(published.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let unpublished = WriteBuilder::new()
        .data(Data::from(b"unpublished".to_vec()))
        .schema("post")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unpublished.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice (owner) queries for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);

    // --------------------------------------------------
    // Bob (not owner) queries for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);

    // --------------------------------------------------
    // Alice publishes the unpublished record.
    // --------------------------------------------------
    let published = WriteBuilder::from(unpublished)
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(published.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice (owner) queries for published records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Anonymous query for published record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .build()
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
}

// Should not be able to query for unpublished records when not authorized.
#[tokio::test]
async fn unpublished() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates 2 records: 1 published and 1 unpublished.
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"record 1".to_vec()))
        .schema("post")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(published.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let unpublished = WriteBuilder::new()
        .data(Data::from(b"record 1".to_vec()))
        .schema("post")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unpublished.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the unpublished record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Bob unsuccessfully queries for unpublished record.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    assert!(reply.body.entries.is_none());

    // --------------------------------------------------
    // Alice publishes the unpublished record.
    // --------------------------------------------------
    let published = WriteBuilder::from(unpublished)
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(published.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries without setting `published` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post"))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Bob queries using the `published` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(true))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Alice unsuccessfully queries for unpublished records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("post").published(false))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    assert!(reply.body.entries.is_none());
}

// Should be able to query for a record by data_cid.
#[tokio::test]
async fn data_cid() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let stream = Cursor::new(br#"{"message": "test record write"}"#.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(stream))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries using the `data_cid` filter.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_cid(write.descriptor.data_cid))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should be able to query for a record by data_size (half-open range).
#[tokio::test]
async fn data_size_part_range() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying data sizes.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::rng().fill_bytes(&mut data);

    let write10 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write10.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let mut data = [0u8; 50];
    rand::rng().fill_bytes(&mut data);

    let write50 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write50.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let mut data = [0u8; 100];
    rand::rng().fill_bytes(&mut data);

    let write100 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write100.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Greater than 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().gt(10)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Less than 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().lt(100)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Greater than or equal to 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().ge(10)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // --------------------------------------------------
    // Less than or equal to 10.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().le(100)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should be able to query for a record by data_size (open or closed range).
#[tokio::test]
async fn data_size_full_range() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying data sizes.
    // --------------------------------------------------
    let mut data = [0u8; 10];
    rand::rng().fill_bytes(&mut data);

    let write10 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write10.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let mut data = [0u8; 50];
    rand::rng().fill_bytes(&mut data);

    let write50 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write50.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let mut data = [0u8; 100];
    rand::rng().fill_bytes(&mut data);

    let write100 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write100.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Greater than 10, less than 60.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().gt(10).lt(60)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Greater than or equal to 10, less than 60.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().ge(10).lt(60)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // Greater than 50, less than or equal to 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().gt(50).le(100)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Greater than or equal to 10, less than or equal to 100.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().data_size(Range::new().ge(10).le(100)))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should be able to query for records where date_created is within a specfied range.
#[tokio::test]
async fn date_created_range() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = WriteBuilder::new()
        .data(Data::from(b"2022".to_vec()))
        .date_created(first_2022.into())
        .message_timestamp(first_2022.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = WriteBuilder::new()
        .data(Data::from(b"2023".to_vec()))
        .date_created(first_2023.into())
        .message_timestamp(first_2023.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = WriteBuilder::new()
        .data(Data::from(b"2024".to_vec()))
        .date_created(first_2024.into())
        .message_timestamp(first_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should not return records that were published and then unpublished.
#[tokio::test]
async fn published_unpublished() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = WriteBuilder::new()
        .data(Data::from(b"2022".to_vec()))
        .date_created(first_2022.into())
        .message_timestamp(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = WriteBuilder::new()
        .data(Data::from(b"2023".to_vec()))
        .date_created(first_2023.into())
        .message_timestamp(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = WriteBuilder::new()
        .data(Data::from(b"2024".to_vec()))
        .date_created(first_2024.into())
        .message_timestamp(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Confirm range before unpublishing.
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Confirm published before unpublishing.
    // --------------------------------------------------
    // owner-requested date range
    let owner_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(owner_range.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    // owner-requested date range
    let owner_published = QueryBuilder::new()
        .filter(RecordsFilter::new().published(true))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply =
        node.request(owner_published.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // anonymous request date range
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .build()
        .expect("should create query");
    let reply = node.request(anon_range.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // anonymous `published` filter
    let anon_published = QueryBuilder::new()
        .filter(RecordsFilter::new().published(true))
        .date_sort(Sort::CreatedAsc)
        .build()
        .expect("should create query");
    let reply = node.request(anon_range.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // --------------------------------------------------
    // Unpublish.
    // --------------------------------------------------
    let unwrite_2022 = WriteBuilder::from(write_2022)
        .published(false)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unwrite_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let unwrite_2023 = WriteBuilder::from(write_2023)
        .published(false)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unwrite_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let unwrite_2024 = WriteBuilder::from(write_2024)
        .published(false)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unwrite_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Earlier anonymous requests should return no results.
    // --------------------------------------------------
    // published date range filter
    let reply = node.request(anon_range).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());

    // published 'true' filter
    let reply = node.request(anon_published).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());

    // --------------------------------------------------
    // Earlier anonymous requests should return no results.
    // --------------------------------------------------
    // published date range filter
    let reply = node.request(owner_range).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());

    // published 'true' filter
    let reply = node.request(owner_published).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());
}

// Should be able to query by date published.
#[tokio::test]
async fn date_published() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = WriteBuilder::new()
        .data(Data::from(b"2022".to_vec()))
        .date_created(first_2022.into())
        .message_timestamp(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = WriteBuilder::new()
        .data(Data::from(b"2023".to_vec()))
        .date_created(first_2023.into())
        .message_timestamp(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = WriteBuilder::new()
        .data(Data::from(b"2024".to_vec()))
        .date_created(first_2024.into())
        .message_timestamp(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Anonymous request should return  results.
    // --------------------------------------------------
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .build()
        .expect("should create query");
    let reply = node.request(anon_range.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);

    // --------------------------------------------------
    // Non-owner request should return  results.
    // --------------------------------------------------
    let anon_range = QueryBuilder::new()
        .filter(RecordsFilter::new().date_published(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::CreatedAsc)
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(anon_range.clone()).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should be able to query by date updated.
#[tokio::test]
async fn date_updated() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2021 = DateTime::parse_from_rfc3339("2021-01-01T00:00:00-00:00").unwrap();

    let write_1 = WriteBuilder::new()
        .data(Data::from(b"write_1".to_vec()))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2 = WriteBuilder::new()
        .data(Data::from(b"write_2".to_vec()))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_3 = WriteBuilder::new()
        .data(Data::from(b"write_3".to_vec()))
        .message_timestamp(first_2021.into())
        .date_created(first_2021.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_3.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Publish records (thereby updating them)
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();

    let write_2022 = WriteBuilder::from(write_1)
        .data(Data::from(b"2022".to_vec()))
        .message_timestamp(first_2022.into())
        .published(true)
        .date_published(first_2022.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2023 = WriteBuilder::from(write_2)
        .data(Data::from(b"2023".to_vec()))
        .message_timestamp(first_2023.into())
        .published(true)
        .date_published(first_2023.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2024 = WriteBuilder::from(write_3)
        .data(Data::from(b"2024".to_vec()))
        .message_timestamp(first_2024.into())
        .published(true)
        .date_published(first_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // From (greater than).
    // --------------------------------------------------
    let last_2022 = DateTime::parse_from_rfc3339("2022-12-31T00:00:00-00:00").unwrap();
    let last_2023 = DateTime::parse_from_rfc3339("2023-12-31T00:00:00-00:00").unwrap();
    let last_2024 = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_updated(DateRange::new().gt(last_2022.into())))
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);

    // --------------------------------------------------
    // To (less than).
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_updated(DateRange::new().lt(last_2023.into())))
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should be able use range and exact match queries together.
#[tokio::test]
async fn range_and_match() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records with varying created dates.
    // --------------------------------------------------
    let first_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let write_2022 = WriteBuilder::new()
        .data(Data::from(b"2022".to_vec()))
        .date_created(first_2022.into())
        .message_timestamp(first_2022.into())
        .schema("2022And2023Schema")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2022.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let write_2023 = WriteBuilder::new()
        .data(Data::from(b"2023".to_vec()))
        .date_created(first_2023.into())
        .message_timestamp(first_2023.into())
        .schema("2022And2023Schema")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2023.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let first_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();
    let write_2024 = WriteBuilder::new()
        .data(Data::from(b"2024".to_vec()))
        .date_created(first_2024.into())
        .message_timestamp(first_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2024.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_2023.record_id);
}

// Should include `authorization` in returned records.
#[tokio::test]
async fn authorization() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"data".to_vec()))
        .schema("schema")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the record, expecting to find `authorization` property.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.authorization.author().unwrap(), alice.did(),);
}

// Should include `attestation` in returned records.
#[tokio::test]
async fn attestation() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"data".to_vec()))
        .schema("schema")
        .attest(&[alice])
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for the record, expecting to find `authorization` property.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    assert_eq!(entries[0].write.authorization.author().unwrap(), alice.did(),);
}

// Should exclude unpublished records when sorting on `date_published`.
#[tokio::test]
async fn exclude_unpublished() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 2 records, 1 published the other unpublished.
    // --------------------------------------------------
    let published = WriteBuilder::new()
        .data(Data::from(b"published".to_vec()))
        .schema("schema")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should) create write");
    let reply = node.request(published.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let unpublished = WriteBuilder::new()
        .data(Data::from(b"unpublised".to_vec()))
        .schema("schema")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unpublished.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Sorting by `date_published` should not include unpublished records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, published.record_id);
}

// Should sort records if `date_sort` is specified (with and without a cursor).
#[tokio::test]
async fn date_sort() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records.
    // --------------------------------------------------
    let ts_2022 = DateTime::parse_from_rfc3339("2022-01-01T00:00:00-00:00").unwrap();
    let ts_2023 = DateTime::parse_from_rfc3339("2023-01-01T00:00:00-00:00").unwrap();
    let ts_2024 = DateTime::parse_from_rfc3339("2024-01-01T00:00:00-00:00").unwrap();

    let write_1 = WriteBuilder::new()
        .data(Data::from(b"write_1".to_vec()))
        .schema("schema")
        .published(true)
        .date_created(ts_2022.into())
        .message_timestamp(ts_2022.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2 = WriteBuilder::new()
        .data(Data::from(b"write_2".to_vec()))
        .schema("schema")
        .published(true)
        .date_created(ts_2023.into())
        .message_timestamp(ts_2023.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_3 = WriteBuilder::new()
        .data(Data::from(b"write_3".to_vec()))
        .schema("schema")
        .published(true)
        .date_created(ts_2024.into())
        .message_timestamp(ts_2024.into())
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_3.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // CreatedAscending: sort
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedAscending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(1))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);

    // --------------------------------------------------
    // CreatedAscending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDesc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_3.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDesc)
        .pagination(Pagination::new().limit(1))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_3.record_id);

    // --------------------------------------------------
    // CreatedDescending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDesc)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAsc)
        .pagination(Pagination::new().limit(1))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);

    // --------------------------------------------------
    // PublishedAscending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedAsc)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDesc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, write_3.record_id);
    assert_eq!(entries[1].write.record_id, write_2.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort with pagination.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDesc)
        .pagination(Pagination::new().limit(1))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_3.record_id);

    // --------------------------------------------------
    // PublishedDescending: sort with pagination cursor.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::PublishedDesc)
        .pagination(Pagination::new().cursor(query_reply.cursor.unwrap()).limit(2))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].write.record_id, write_2.record_id);
}

// Should tiebreak using `message_cid` when sorting identical values.
#[tokio::test]
async fn sort_identical() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 3 records.
    // --------------------------------------------------
    let timestamp = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    let write_1 = WriteBuilder::new()
        .data(Data::from(b"write_1".to_vec()))
        .date_created(timestamp.into())
        .message_timestamp(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_2 = WriteBuilder::new()
        .data(Data::from(b"write_2".to_vec()))
        .date_created(timestamp.into())
        .message_timestamp(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let write_3 = WriteBuilder::new()
        .data(Data::from(b"write_3".to_vec()))
        .date_created(timestamp.into())
        .message_timestamp(timestamp.into())
        .schema("schema")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    // reverse sort newest to oldest by message_cid
    let mut sorted_write = [write_1.clone(), write_2.clone(), write_3.clone()];
    sorted_write.sort_by_key(|b| std::cmp::Reverse(b.cid().unwrap()));

    let reply = node.request(write_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    let reply = node.request(write_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    let reply = node.request(write_3.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // CreatedAscending: verify messages returned are sorted by `message_cid`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedAsc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.cid().unwrap(), sorted_write[2].cid().unwrap());
    assert_eq!(entries[1].write.record_id, sorted_write[1].record_id);

    // --------------------------------------------------
    // CreatedDescending: verify messages returned are sorted by `message_cid`
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("schema"))
        .date_sort(Sort::CreatedDesc)
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].write.record_id, sorted_write[0].record_id);
    assert_eq!(entries[1].write.record_id, sorted_write[1].record_id);
}

// Should paginate all records in ascending order.
#[tokio::test]
async fn paginate_ascending() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 12 records.
    // --------------------------------------------------
    let mut writes = vec![];
    let mut date_created = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    for i in 0..12 {
        date_created -= Duration::days(1);

        let write = WriteBuilder::new()
            .date_created(date_created.into())
            .message_timestamp(date_created.into())
            .data(Data::from(format!("write_{i}").into_bytes()))
            .schema("schema")
            .published(true)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
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
            .date_sort(Sort::CreatedAsc)
            .pagination(Pagination { limit: Some(5), cursor })
            .sign(alice)
            .build()
            .await
            .expect("should create query");
        let reply = node.request(query).owner(alice.did()).await.expect("should query");
        assert_eq!(reply.status, StatusCode::OK);

        let query_reply: QueryReply = reply.body;
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
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice creates 12 records.
    // --------------------------------------------------
    let mut writes = vec![];
    let mut date_created = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();

    for i in 0..12 {
        date_created += Duration::days(1);

        let write = WriteBuilder::new()
            .data(Data::from(format!("write_{i}").into_bytes()))
            .schema("schema")
            .published(true)
            .date_created(date_created.into())
            .message_timestamp(date_created.into())
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
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
            .date_sort(Sort::CreatedDesc)
            .pagination(Pagination { limit: Some(5), cursor })
            .sign(alice)
            .build()
            .await
            .expect("should create query");
        let reply = node.request(query).owner(alice.did()).await.expect("should query");
        assert_eq!(reply.status, StatusCode::OK);

        let query_reply: QueryReply = reply.body;
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
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Create records.
    // --------------------------------------------------
    let write_1 = WriteBuilder::new()
        .data(Data::from(b"schema1".to_vec()))
        .schema("http://schema1")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2 = WriteBuilder::new()
        .data(Data::from(b"schema2".to_vec()))
        .schema("http://schema2")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Query anonymously.
    // --------------------------------------------------
    let early_date = DateTime::parse_from_rfc3339("2000-01-01T00:00:00-00:00").unwrap();

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().date_created(DateRange::new().gt(early_date.into())))
        .build()
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, write_1.record_id);
}

// Should only return records meant for the specified recipient(s).
#[tokio::test]
async fn recipient_query() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records each for Bob and Carol; 2 public, 2 private.
    // --------------------------------------------------
    let alice_bob_private = WriteBuilder::new()
        .data(Data::from(b"Hello Bob (private)".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_bob_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_bob_public = WriteBuilder::new()
        .data(Data::from(b"Hello Bob (public)".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_bob_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_carol_private = WriteBuilder::new()
        .data(Data::from(b"Hello Carol (private)".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_carol_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_carol_public = WriteBuilder::new()
        .data(Data::from(b"Hello Carol (public)".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_carol_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol creates 2 records each for Alice and Bob; 2 public, 2 private.
    // --------------------------------------------------
    let carol_alice_private = WriteBuilder::new()
        .data(Data::from(b"Hello Alice (private)".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_alice_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_alice_public = WriteBuilder::new()
        .data(Data::from(b"Hello Alice (public)".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_alice_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_bob_private = WriteBuilder::new()
        .data(Data::from(b"Hello Bob (private)".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_bob_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_bob_public = WriteBuilder::new()
        .data(Data::from(b"Hello Bob (public)".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .published(true)
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_bob_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob creates 2 records each for Alice and Carol; 2 public, 2 private.
    // --------------------------------------------------
    let bob_alice_private = WriteBuilder::new()
        .data(Data::from(b"Hello Alice (private)".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_alice_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_alice_public = WriteBuilder::new()
        .data(Data::from(b"Hello Alice (public)".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_alice_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_carol_private = WriteBuilder::new()
        .data(Data::from(b"Hello Carol (private)".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_carol_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_carol_public = WriteBuilder::new()
        .data(Data::from(b"Hello Carol (public)".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_carol_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for messages with himself and Alice as recipients.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_recipient(bob.did())
                .add_recipient(alice.did()),
        )
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_recipient(carol.did()),
        )
        .sign(carol)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_recipient(alice.did())
                .add_recipient(bob.did())
                .published(true),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_recipient(carol.did())
                .add_recipient(alice.did())
                .published(false),
        )
        .sign(carol)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 records each for Bob and Carol: 1 public, 1 private.
    // --------------------------------------------------
    let alice_bob_private = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_bob_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_bob_public = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_bob_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_carol_private = WriteBuilder::new()
        .data(Data::from(b"Hello Carol".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_carol_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let alice_carol_public = WriteBuilder::new()
        .data(Data::from(b"Hello Carol".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(alice_carol_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol creates 2 records each for Alice and Bob: 1 public, 1 private.
    // --------------------------------------------------
    let carol_alice_private = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_alice_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_alice_public = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_alice_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_bob_private = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_bob_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let carol_bob_public = WriteBuilder::new()
        .data(Data::from(b"Hello Bob".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .published(true)
        .data_format("application/json")
        .sign(carol)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(carol_bob_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob creates 2 records each for Alice and Carol: 1 public, 1 private.
    // --------------------------------------------------
    let bob_alice_private = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_alice_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_alice_public = WriteBuilder::new()
        .data(Data::from(b"Hello Alice".to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_alice_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_carol_private = WriteBuilder::new()
        .data(Data::from(b"Hello Carol".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_carol_private.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_carol_public = WriteBuilder::new()
        .data(Data::from(b"Hello Carol".to_vec()))
        .recipient(carol.did())
        .protocol(ProtocolBuilder {
            protocol: "http://allow-any.xyz",
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema("post")
        .data_format("application/json")
        .published(true)
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(bob_carol_public.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob queries for messages with himself and Alice as authors.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://allow-any.xyz")
                .protocol_path("post")
                .add_author(bob.did())
                .add_author(alice.did()),
        )
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_author(carol.did()),
        )
        .sign(carol)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_author(alice.did())
                .add_author(bob.did())
                .published(true),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
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
                .add_author(carol.did())
                .add_author(alice.did())
                .published(false),
        )
        .sign(carol)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");

    // Carol should be able to see 3 messages
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|e| e.write.record_id == alice_carol_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_alice_private.record_id));
    assert!(entries.iter().any(|e| e.write.record_id == carol_bob_private.record_id));
}

// Should only return records authored by the specified author(s).
#[tokio::test]
async fn paginate_non_owner() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Public records.
    // --------------------------------------------------
    let mut timestamp = DateTime::parse_from_rfc3339("2024-12-31T00:00:00-00:00").unwrap();
    let mut sorted_writes = vec![];

    // Bob
    for i in 0..5 {
        timestamp += Duration::minutes(1);

        let write = WriteBuilder::new()
            .message_timestamp(timestamp.into())
            .date_created(timestamp.into())
            .data(Data::from(format!("bob_private_{i}").into_bytes()))
            .protocol(ProtocolBuilder {
                protocol: "http://allow-any.xyz",
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema("post")
            .published(true)
            .sign(bob)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        sorted_writes.push(write);
    }

    // Alice
    for i in 0..5 {
        timestamp += Duration::minutes(1);

        let write = WriteBuilder::new()
            .message_timestamp(timestamp.into())
            .date_created(timestamp.into())
            .data(Data::from(format!("alice_private_{i}").into_bytes()))
            .protocol(ProtocolBuilder {
                protocol: "http://allow-any.xyz",
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema("post")
            .published(true)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        sorted_writes.push(write);
    }

    // --------------------------------------------------
    // Private records.
    // --------------------------------------------------
    // Alice
    for i in 0..5 {
        timestamp += Duration::minutes(1);

        let write = WriteBuilder::new()
            .message_timestamp(timestamp.into())
            .date_created(timestamp.into())
            .data(Data::from(format!("alice_public_{i}").into_bytes()))
            .protocol(ProtocolBuilder {
                protocol: "http://allow-any.xyz",
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema("post")
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        sorted_writes.push(write);
    }

    // Bob
    for i in 0..5 {
        timestamp += Duration::minutes(1);

        let write = WriteBuilder::new()
            .message_timestamp(timestamp.into())
            .date_created(timestamp.into())
            .data(Data::from(format!("bob_public_{i}").into_bytes()))
            .protocol(ProtocolBuilder {
                protocol: "http://allow-any.xyz",
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema("post")
            .sign(bob)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        sorted_writes.push(write);
    }

    // Alice for Bob
    for i in 0..5 {
        timestamp += Duration::minutes(1);

        let write = WriteBuilder::new()
            .message_timestamp(timestamp.into())
            .date_created(timestamp.into())
            .data(Data::from(format!("alice_public_{i}").into_bytes()))
            .protocol(ProtocolBuilder {
                protocol: "http://allow-any.xyz",
                protocol_path: "post",
                parent_context_id: None,
            })
            .schema("post")
            .recipient(bob.did())
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        sorted_writes.push(write);
    }

    // sort oldest to newest
    sorted_writes.sort_by(|a, b| {
        a.descriptor.base.message_timestamp.cmp(&b.descriptor.base.message_timestamp)
    });

    // --------------------------------------------------
    // Alice fetches all records.
    // -------------------------------------------------
    let mut all_entries = vec![];

    // page 1
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://allow-any.xyz").protocol_path("post"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(10))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 10);
    all_entries.extend(entries);

    // page 2
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://allow-any.xyz").protocol_path("post"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(10).cursor(query_reply.cursor.unwrap()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 10);
    all_entries.extend(entries);

    // page 3
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://allow-any.xyz").protocol_path("post"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(5).cursor(query_reply.cursor.unwrap()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 5);
    all_entries.extend(entries);

    assert!(query_reply.cursor.is_none());
    for i in 0..25 {
        assert_eq!(all_entries[i].write.record_id, sorted_writes[i].record_id);
    }

    // --------------------------------------------------
    // Bob fetches records he has permission to access.
    // -------------------------------------------------
    let mut all_entries = vec![];

    // page 1
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://allow-any.xyz").protocol_path("post"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(10))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 10);
    all_entries.extend(entries);

    // page 2
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://allow-any.xyz").protocol_path("post"))
        .date_sort(Sort::CreatedAsc)
        .pagination(Pagination::new().limit(10).cursor(query_reply.cursor.unwrap()))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 10);
    all_entries.extend(entries);

    assert!(query_reply.cursor.is_none());

    // filter sorted records for Bob
    let bob_sorted = sorted_writes
        .iter()
        .filter(|w| {
            authorization::kid_did(&w.authorization.signature).unwrap() == bob.did()
                || w.descriptor.recipient.clone().unwrap_or_default() == bob.did()
                || w.descriptor.published.unwrap_or_default()
        })
        .collect::<Vec<_>>();

    for i in 0..20 {
        assert_eq!(all_entries[i].write.record_id, bob_sorted[i].record_id);
    }
}

// Should treat records where `published` set to false as unpublished.
#[tokio::test]
async fn published_false() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice creates an unpublished record.
    // -------------------------------------------------
    let unpublished = WriteBuilder::new()
        .data(Data::from(b"1".to_vec()))
        .schema("http://schema1")
        .published(false)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(unpublished.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches the unpublished record.
    // -------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("http://schema1"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    // --------------------------------------------------
    // Bob attempts to fetch the unpublished record, but fails.
    // -------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("http://schema1"))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());
}

// Should not fetch entries across tenants.
#[tokio::test]
async fn tenant_bound() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // 2 owners create records.
    // -------------------------------------------------
    let alice_write = WriteBuilder::new()
        .data(Data::from(b"1".to_vec()))
        .schema("http://schema1")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_write).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bob_write = WriteBuilder::new()
        .data(Data::from(b"1".to_vec()))
        .schema("http://schema1")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bob_write).owner(bob.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice fetches her record.
    // -------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("http://schema1"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
}

// Should return a status of BadRequest (400) if protocol is not normalized.
#[tokio::test]
async fn bad_protocol() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("example.com/"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    // builder corrects invalid protocols
    query.descriptor.filter.protocol = Some("example.com/".to_string());

    let Err(Error::BadRequest(msg)) = node.request(query).owner(alice.did()).await else {
        panic!("should return BadRequest");
    };
    assert_eq!(msg, "invalid URL: example.com/");
}

// Should return a status of BadRequest (400) if schema is not normalized.
#[tokio::test]
async fn bad_schema() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("example.com/"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    // builder corrects invalid protocols
    query.descriptor.filter.schema = Some("example.com/".to_string());

    let Err(Error::BadRequest(msg)) = node.request(query).owner(alice.did()).await else {
        panic!("should return BadRequest");
    };
    assert_eq!(msg, "invalid URL: example.com/");
}

// Should return a status of BadRequest (400) when published is `false` and a `date_published` is set.
#[tokio::test]
async fn bad_date_published() {
    let node = node().await;
    let alice = alice().await;

    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new().published(false).date_published(DateRange::new().gt(Utc::now())),
        )
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should return BadRequest");
    };
    assert!(e.contains("validation failed:"));
}

// Should return a status of Forbidden (403) when anonymous query has filter
// explicitly for unpublished records.
#[tokio::test]
async fn anonymous_unpublished() {
    let node = node().await;
    let alice = alice().await;

    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().published(false).schema("http://schema"))
        .build()
        .expect("should create query");
    let Err(Error::Forbidden(msg)) = node.request(query).owner(alice.did()).await else {
        panic!("should return BadRequest");
    };
    assert_eq!(msg, "missing authorization");
}

// Should return messages scoped to the specified `context_id`.
#[tokio::test]
async fn context_id() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures a nested protocol (foo->bar->baz).
    // --------------------------------------------------
    let nested = include_bytes!("../examples/protocols/nested.json");
    let definition: Definition = serde_json::from_slice(nested).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 foo records.
    // --------------------------------------------------
    let foo_1 = WriteBuilder::new()
        .data(Data::from(b"foo_1".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .schema("foo")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(foo_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let foo_2 = WriteBuilder::new()
        .data(Data::from(b"foo_2".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .schema("foo")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(foo_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 foo/bar records.
    // --------------------------------------------------
    let bar_1 = WriteBuilder::new()
        .data(Data::from(b"bar_1".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar",
            parent_context_id: foo_1.context_id.clone(),
        })
        .schema("bar")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bar_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let bar_2 = WriteBuilder::new()
        .data(Data::from(b"bar_2".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar",
            parent_context_id: foo_1.context_id.clone(),
        })
        .schema("bar")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bar_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 foo/bar/baz records.
    // --------------------------------------------------
    let baz_1 = WriteBuilder::new()
        .data(Data::from(b"baz_1".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar/baz",
            parent_context_id: bar_1.context_id.clone(),
        })
        .schema("baz")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(baz_1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let baz_2 = WriteBuilder::new()
        .data(Data::from(b"baz_2".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://nested.xyz",
            protocol_path: "foo/bar/baz",
            parent_context_id: bar_1.context_id.clone(),
        })
        .schema("baz")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(baz_2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice queries for records in foo_1 path.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().context_id(foo_1.context_id.unwrap()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 5);

    let record_ids = entries.iter().map(|e| &e.write.record_id).collect::<Vec<_>>();
    assert!(record_ids.contains(&&foo_1.record_id));
    assert!(record_ids.contains(&&bar_1.record_id));
    assert!(record_ids.contains(&&bar_2.record_id));
    assert!(record_ids.contains(&&baz_1.record_id));
    assert!(record_ids.contains(&&baz_2.record_id));

    // --------------------------------------------------
    // Alice queries for records in bar_1 path.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().context_id(bar_1.context_id.unwrap()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    let record_ids = entries.iter().map(|e| &e.write.record_id).collect::<Vec<_>>();
    assert!(record_ids.contains(&&bar_1.record_id));
    assert!(record_ids.contains(&&baz_1.record_id));
    assert!(record_ids.contains(&&baz_2.record_id));

    // --------------------------------------------------
    // Alice queries for records in baz_1 path.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().context_id(baz_1.context_id.unwrap()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);

    assert!(entries.iter().map(|e| &e.write.record_id).any(|x| x == &baz_1.record_id));
}

// Should not use protocol authorization if protocol_role is not set.
#[tokio::test]
async fn protocol_no_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a thread protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a thread record.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"A new thread".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(thread.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat record addressed to BOB.
    // --------------------------------------------------
    let chat_bob = WriteBuilder::new()
        .data(Data::from(b"Bob can read this".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .published(false)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(chat_bob.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 more chat records NOT addressed to BOB.
    // --------------------------------------------------
    for _ in 0..2 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob cannot read this".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://thread-role.xyz",
                protocol_path: "thread/chat",
                parent_context_id: thread.context_id.clone(),
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob queries without invoking protocol role.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://thread-role.xyz"))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, chat_bob.record_id);

    // --------------------------------------------------
    // Bob queries without invoking protocol role and only unpublished records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://thread-role.xyz").published(false))
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].write.record_id, chat_bob.record_id);
}

// Should allow queries authorized using a root-level role.
#[tokio::test]
async fn protocol_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a 'friend' role record with Bob as recipient.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bob_friend.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://friend-role.xyz",
                protocol_path: "chat",
                parent_context_id: None,
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob queries uses his friend role to query for records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://friend-role.xyz").protocol_path("chat"))
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);

    // --------------------------------------------------
    // Bob uses his friend role and an 'unpublished' filter to query for records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://friend-role.xyz")
                .protocol_path("chat")
                .published(false),
        )
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should allow queries authorize using a context role.
#[tokio::test]
async fn context_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(thread.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a 'participant' role record with Bob as recipient.
    // --------------------------------------------------
    let participant_role = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(participant_role.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://thread-role.xyz",
                protocol_path: "thread/chat",
                parent_context_id: thread.context_id.clone(),
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob uses his 'friend' role to query for chat records.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://thread-role.xyz")
                .protocol_path("thread/chat")
                .context_id(thread.context_id.unwrap()),
        )
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let reply = node.request(query).owner(alice.did()).await.expect("should query");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 3);
}

// Should not execute protocol queries where `protocol_path` is missing.
#[tokio::test]
async fn no_protocol_path() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a friend role record.
    // --------------------------------------------------
    let friend = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(friend.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://friend-role.xyz",
                protocol_path: "chat",
                parent_context_id: None,
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob uses his 'friend' role to query for chat records BUT does not have `protocol_path` set.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://friend-role.xyz"))
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "missing `protocol_path`");
}

// Should not execute context role authorized queries when `context_id` is missing.
#[tokio::test]
async fn no_context_id() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a friend role record.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        // .context_id() deliberately omitted
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(thread.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a 'participant' role record with Bob as recipient.
    // --------------------------------------------------
    let participant_role = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        node.request(participant_role.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://thread-role.xyz",
                protocol_path: "thread/chat",
                parent_context_id: thread.context_id.clone(),
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob uses his thread participant role to query BUT omits the `context_id`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new().protocol("http://thread-role.xyz").protocol_path("thread/chat"),
        )
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "missing `context_id`");
}

// Should reject root-level role authorized queries if a matching root-level
// role record is not found for the message author.
#[tokio::test]
async fn no_root_role_record() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend_role = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://friend-role.xyz",
                protocol_path: "chat",
                parent_context_id: None,
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob uses his friend participant role to query.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().protocol("http://friend-role.xyz").protocol_path("chat"))
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let Err(Error::Forbidden(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should reject context role authorized queries if a matching context role record is not found.
#[tokio::test]
async fn no_context_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let thread_role = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread_role).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply =
        node.request(configure).owner(alice.did()).await.expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a thread role record.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        // .context_id() deliberately omitted
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(thread.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 3 chat records.
    // --------------------------------------------------
    for _ in 0..3 {
        let chat = WriteBuilder::new()
            .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
            .recipient(alice.did())
            .protocol(ProtocolBuilder {
                protocol: "http://thread-role.xyz",
                protocol_path: "thread/chat",
                parent_context_id: thread.context_id.clone(),
            })
            .published(false)
            .sign(alice)
            .build()
            .await
            .expect("should create write");
        let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Bob uses his thread participant role to query BUT omits the `context_id`.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol("http://thread-role.xyz")
                .protocol_path("thread/chat")
                .context_id(thread.context_id.unwrap()),
        )
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create query");
    let Err(Error::Forbidden(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should return a status of Unauthorized (401) when signature check fails.
#[tokio::test]
async fn bad_signature() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("http://schema"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    query.authorization.as_mut().unwrap().signature.signatures[0].signature =
        "badsignature".to_string();

    let Err(Error::Unauthorized(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be Unauthorized");
    };
    assert!(e.starts_with("failed to authenticate: "));
}

// Should return a status of BadRequest (400) when the message cannot be parsed.
#[tokio::test]
async fn bad_message() {
    let node = node().await;
    let alice = alice().await;

    let mut query = QueryBuilder::new()
        .filter(RecordsFilter::new().schema("http://schema"))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    query.descriptor.filter = RecordsFilter::default();

    let Err(Error::BadRequest(e)) = node.request(query).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}
