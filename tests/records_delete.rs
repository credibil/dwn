//! Records Delete

use std::io::Read;

use chrono::Days;
use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::{EventLog, KeyStore, MessageStore};
use vercre_dwn::records::{
    Data, DeleteBuilder, DeleteDescriptor, ProtocolBuilder, QueryBuilder, ReadBuilder,
    RecordsFilter, WriteBuilder,
};
use vercre_dwn::{Error, Method, endpoint, store};

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
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the record was written.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&write.record_id);
    let query = QueryBuilder::new()
        .filter(filter)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should find write");
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
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes another record with the same data
    // --------------------------------------------------
    let alice_write2 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, alice_write2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record with the same data
    // --------------------------------------------------
    let bob_write1 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(BOB_DID, bob_write1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes another record with the same data
    // --------------------------------------------------
    let bob_write2 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&bob_keyring)
        .build()
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
    let read = ReadBuilder::new()
        .filter(filter)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should find write");
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
    let read = ReadBuilder::new()
        .filter(filter)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should find write");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should be not found");
    assert_eq!(reply.status.code, StatusCode::NOT_FOUND);
    // TODO: uncomment when NotFound error supports body with initial_write and delete records
    // let Err(Error::NotFound(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
    //     panic!("should be NotFound");
    // };
    // assert_eq!(e, "record is deleted");

    // --------------------------------------------------
    // Bob's record is unaffected.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&bob_write1.record_id);
    let read = ReadBuilder::new()
        .filter(filter)
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should find write");
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
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the initial write's data.
    // --------------------------------------------------
    let data = br#"{"record": "test record write again"}"#;

    let write = WriteBuilder::from(write.clone())
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "doc",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat/tag.
    // --------------------------------------------------
    let data = br#"{"record": "chat tag write"}"#;

    let tag = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post/tag",
            parent_context_id: chat.context_id,
        })
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
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
        .data(Data::from(data.to_vec()))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, post.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a post/comment.
    // --------------------------------------------------
    let data = br#"{"record": "post comment write"}"#;

    let comment = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post/comment",
            parent_context_id: post.context_id,
        })
        .sign(&alice_keyring)
        .build()
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

// Should allow co-delete by invoking a context role.
#[tokio::test]
async fn context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
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
    // Alice creates a thread.
    // --------------------------------------------------
    let data = br#"{"record": "thread write"}"#;

    let thread = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
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
    // Alice adds Bob as a 'thread/admin' for the thread
    // --------------------------------------------------
    let data = br#"{"record": "Bob admin"}"#;

    let admin = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "thread/admin",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, admin.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message on the thread
    // --------------------------------------------------
    let data = br#"{"record": "chat message"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's 'post/comment'.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .build(&carol_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as thread admin) is able to delete the chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .protocol_role("thread/admin")
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should allow co-delete by invoking a root-level role.
#[tokio::test]
async fn root_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol.
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
    // Alice adds Bob as a 'thread/admin' at root level.
    // --------------------------------------------------
    let data = br#"{"record": "Bob admin"}"#;

    let admin = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(BOB_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "admin",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, admin.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message.
    // --------------------------------------------------
    let data = br#"{"record": "a chat message"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(ALICE_DID)
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, chat.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .build(&carol_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as admin) is able to delete the chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .protocol_role("admin")
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);
}

// Should return a status of Forbidden (403) if message is not authorized.
#[tokio::test]
async fn forbidden() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "delete request failed authorization");
}

// Should return a status of Forbidden (403) if message is not authorized.
#[tokio::test]
async fn unauthorized() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id("record_id")
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    delete.authorization.signature.signatures[0].signature = "bad_signature".to_string();

    let Err(Error::Unauthorized(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be Unauthorized");
    };
    assert!(e.starts_with("failed to authenticate"));
}

// Should return a status of BadRequest (400) when message is invalid.
#[tokio::test]
async fn invalid_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id("record_id")
        .build(&alice_keyring)
        .await
        .expect("should create delete");
    delete.descriptor = DeleteDescriptor::default();

    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, delete, &provider).await else {
        panic!("should be BadRequest");
    };
    assert!(e.starts_with("validation failed for "));
}

// FIXME: ignore until we are building full indexes for each data type
// Should index additional properties for the record being deleted.
#[tokio::test]
#[ignore]
async fn index_additional() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .schema("http://test_schema")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check MessageStore and EventLog.
    // --------------------------------------------------
    let query = store::RecordsQuery {
        method: Some(Method::Delete),
        filters: vec![RecordsFilter::new().schema("http://test_schema")],
        include_archived: true,
        ..store::RecordsQuery::default()
    };
    let entries = MessageStore::query(&provider, ALICE_DID, &query.clone().into())
        .await
        .expect("should query");
    assert_eq!(entries.len(), 1);

    // check log
    let (entries, _) =
        EventLog::query(&provider, ALICE_DID, &query.into()).await.expect("should query");
    assert_eq!(entries.len(), 1);
}

// Should log delete event while retaining initial write event.
#[tokio::test]
async fn log_delete() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply = endpoint::handle(ALICE_DID, delete.clone(), &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check EventLog.
    // --------------------------------------------------
    // Write record
    let query = store::RecordsQuery {
        include_archived: true,
        method: None,
        ..store::RecordsQuery::default()
    };
    let (entries, _) =
        EventLog::query(&provider, ALICE_DID, &query.into()).await.expect("should query");
    assert_eq!(entries.len(), 2);
}

// Should delete all writes except the initial write.
#[tokio::test]
async fn delete_updates() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write1 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write2 = WriteBuilder::from(write1.clone())
        .data(Data::from(data.to_vec()))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let reply = endpoint::handle(ALICE_DID, write2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write2.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let reply =
        endpoint::handle(ALICE_DID, delete.clone(), &provider).await.expect("should delete");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check EventLog. There should only be 2 events: the initial write and the delete.
    // --------------------------------------------------
    // Write record
    let query = store::RecordsQuery {
        include_archived: true,
        method: None,
        ..store::RecordsQuery::default()
    };
    let (entries, _) =
        EventLog::query(&provider, ALICE_DID, &query.into()).await.expect("should query");
    assert_eq!(entries.len(), 2);
}
