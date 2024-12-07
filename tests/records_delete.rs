//! Records Delete

use std::io::Read;

use chrono::Days;
use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{
    DeleteBuilder, QueryBuilder, ReadBuilder, RecordsFilter, WriteBuilder, WriteData, WriteProtocol,
};
use vercre_dwn::{Error, endpoint};

// Should successfully delete a record and then fail when attempting to delete it again.
#[tokio::test]
async fn delete_record() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record
    // --------------------------------------------------
    let data = br#"{"record": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the record was written.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&write.record_id);
    let query =
        QueryBuilder::new().filter(filter).build(&alice_keyring).await.expect("should find write");
    let reply = endpoint::handle(ALICE_DID, query.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    // --------------------------------------------------
    // Delete the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure record doesn't appear in query results.
    // --------------------------------------------------
    let reply = endpoint::handle(ALICE_DID, query, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);
    assert!(reply.body.is_none());

    // --------------------------------------------------
    // Deleting the same record should fail.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "cannot delete a `RecordsDelete` record");
}

// Should not affect other records (or tenants) with the same data.
#[tokio::test]
async fn delete_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    let data = br#"{"record": "test record write"}"#;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let alice_write1 = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes another record with the same data
    // --------------------------------------------------
    let alice_write2 = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record with the same data
    // --------------------------------------------------
    let bob_write1 = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&bob_keyring)
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, bob_write1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes another record with the same data
    // --------------------------------------------------
    let bob_write2 = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&bob_keyring)
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, bob_write2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes her first record then checks the second record's data.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&alice_write1.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // ensure the second record's data is unaffected
    let filter = RecordsFilter::new().record_id(&alice_write2.record_id);
    let read =
        ReadBuilder::new().filter(filter).build(&alice_keyring).await.expect("should find write");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");

    let Some(mut data_stream) = body.entry.data else {
        panic!("should have data");
    };

    let mut buffer = Vec::new();
    data_stream.read_to_end(&mut buffer).expect("should read to end");
    assert_eq!(buffer, data);

    // --------------------------------------------------
    // Alice deletes her second record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&alice_write2.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // ensure the second record has been deleted
    let filter = RecordsFilter::new().record_id(&alice_write2.record_id);
    let read =
        ReadBuilder::new().filter(filter).build(&alice_keyring).await.expect("should find write");

    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record");

    // --------------------------------------------------
    // Bob's record is unaffected.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&bob_write1.record_id);
    let read =
        ReadBuilder::new().filter(filter).build(&bob_keyring).await.expect("should find write");
    let reply = endpoint::handle(BOB_DID, read, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");

    let Some(mut data_stream) = body.entry.data else {
        panic!("should have data");
    };

    let mut buffer = Vec::new();
    data_stream.read_to_end(&mut buffer).expect("should read to end");
    assert_eq!(buffer, data);
}

// Should return a status of NotFound (404) when deleting a non-existent record.
#[tokio::test]
async fn not_found() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let delete = DeleteBuilder::new()
        .record_id("imaginary_record_id")
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record found");
}

// Should disallow delete when there is a newer record.
#[tokio::test]
async fn newer_version() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let data = br#"{"record": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the initial write's data.
    // --------------------------------------------------
    let data = br#"{"record": "test record write again"}"#;

    let write = WriteBuilder::new()
        .existing(write.clone())
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to delete the initial write but fails.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    // fake older timestamp
    let timestamp = write.descriptor.base.message_timestamp;
    delete.descriptor.base.message_timestamp =
        timestamp.checked_sub_days(Days::new(1)).expect("should subtract days");

    let Err(Error::Conflict(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "newer record version exists");
}

// Should be able to delete and then rewrite the same data.
#[tokio::test]
async fn rewrite_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    let data = br#"{"record": "test record write"}"#;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes another record with the same data.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow delete using the 'allow-anyone' rule.
#[tokio::test]
async fn anyone_delete() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../crates/dwn-test/protocols/anyone-collaborate.json");
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
    // Alice writes a record.
    // --------------------------------------------------
    let data = br#"{"record": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol,
            protocol_path: "doc".to_string(),
        })
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob (or anyone else) successfully deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow recipient to delete using an ancestor recipient rule.
#[tokio::test]
async fn ancestor_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let recipient_can = include_bytes!("../crates/dwn-test/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient_can).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat record with Bob as the recipient.
    // --------------------------------------------------
    let data = br#"{"record": "chat write"}"#;

    let chat = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol.clone(),
            protocol_path: "post".to_string(),
        })
        .recipient(BOB_DID)
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat/tag.
    // --------------------------------------------------
    let data = br#"{"record": "chat tag write"}"#;

    let tag = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol,
            protocol_path: "post/tag".to_string(),
        })
        .parent_context_id(chat.context_id.unwrap())
        .build(&alice_keyring)
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, tag.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete the chat/tag.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&tag.record_id)
        .build(&carol_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as recipient) is able to delete the chat/tag.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&tag.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow recipient to delete using a recipient rule.
#[tokio::test]
async fn direct_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let recipient_can = include_bytes!("../crates/dwn-test/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient_can).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");

    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat record with Bob as the recipient.
    // --------------------------------------------------
    let data = br#"{"record": "chat write"}"#;

    let chat = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol.clone(),
            protocol_path: "post".to_string(),
        })
        .recipient(BOB_DID)
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete the chat record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .build(&carol_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as recipient) is able to delete the chat record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow the author to delete with ancestor author rule.
#[tokio::test]
async fn ancestor_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
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
    // Bob writes a post on Alice's 'feed'.
    // --------------------------------------------------
    let data = br#"{"record": "post write"}"#;

    let post = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol.clone(),
            protocol_path: "post".to_string(),
        })
        .build(&bob_keyring)
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, post.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a post/comment.
    // --------------------------------------------------
    let data = br#"{"record": "post comment write"}"#;

    let comment = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .protocol(WriteProtocol {
            protocol: definition.protocol.clone(),
            protocol_path: "post/comment".to_string(),
        })
        .parent_context_id(post.context_id.unwrap())
        .build(&alice_keyring)
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, comment.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's 'post/comment'.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&comment.record_id)
        .build(&carol_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as post author) is able to delete the post comment.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&comment.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}
