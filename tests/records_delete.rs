//! Records Delete

#![cfg(all(feature = "client", feature = "server"))]

use std::io::Read;

use chrono::Days;
use credibil_dwn::api::Client;
use credibil_dwn::client::messages;
use credibil_dwn::client::messages::MessagesFilter;
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{
    Data, DeleteBuilder, DeleteDescriptor, ProtocolBuilder, QueryBuilder, ReadBuilder,
    RecordsFilter, WriteBuilder,
};
use credibil_dwn::interfaces::records::ReadReply;
use credibil_dwn::provider::{EventLog, MessageStore};
use credibil_dwn::{Error, Interface, Method, StatusCode, store};
use test_utils::{Identity, Provider};
use tokio::sync::OnceCell;

static ALICE: OnceCell<Identity> = OnceCell::const_new();
static BOB: OnceCell<Identity> = OnceCell::const_new();
static CAROL: OnceCell<Identity> = OnceCell::const_new();
static NODE: OnceCell<Client<Provider>> = OnceCell::const_new();

async fn alice() -> &'static Identity {
    ALICE.get_or_init(|| async { Identity::new("records_delete_alice").await }).await
}
async fn bob() -> &'static Identity {
    BOB.get_or_init(|| async { Identity::new("records_delete_bob").await }).await
}
async fn carol() -> &'static Identity {
    CAROL.get_or_init(|| async { Identity::new("records_delete_carol").await }).await
}
async fn node() -> &'static Client<Provider> {
    NODE.get_or_init(|| async { Client::new(Provider::new().await) }).await
}

// Should successfully delete a record and then fail when attempting to delete it again.
#[tokio::test]
async fn delete_record() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record
    // --------------------------------------------------
    let data = br#"{"record": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the record was written.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&write.record_id);
    let query =
        QueryBuilder::new().filter(filter).sign(alice).build().await.expect("should find write");
    let reply = node.request(query.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    // --------------------------------------------------
    // Delete the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure record doesn't appear in query results.
    // --------------------------------------------------
    let reply = node.request(query).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.entries.is_none());

    // --------------------------------------------------
    // Deleting the same record should fail.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::NotFound(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "cannot delete a `RecordsDelete` record");
}

// Should not affect other records (or tenants) with the same data.
#[tokio::test]
async fn delete_data() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    let data = br#"{"record": "test record write"}"#;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let alice_write1 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_write1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes another record with the same data
    // --------------------------------------------------
    let alice_write2 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(alice_write2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record with the same data
    // --------------------------------------------------
    let bob_write1 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bob_write1.clone()).owner(bob.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes another record with the same data
    // --------------------------------------------------
    let bob_write2 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(bob_write2.clone()).owner(bob.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes her first record then checks the second record's data.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&alice_write1.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // ensure the second record's data is unaffected
    let filter = RecordsFilter::new().record_id(&alice_write2.record_id);
    let read =
        ReadBuilder::new().filter(filter).sign(alice).build().await.expect("should find write");
    let reply = node.request(read).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let Some(mut data_stream) = read_reply.entry.data else {
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
        .sign(alice)
        .build()
        .await
        .expect("should create delete");
    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // ensure the second record has been deleted
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&alice_write2.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should find write");
    let reply = node.request(read).owner(alice.did()).await.expect("should be not found");
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // TODO: uncomment when NotFound error supports body with initial_write and delete records
    // let Err(Error::NotFound(e)) = endpoint::handle(alice.did(), read, &provider).await else {
    //     panic!("should be NotFound");
    // };
    // assert_eq!(e, "record is deleted");

    // --------------------------------------------------
    // Bob's record is unaffected.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&bob_write1.record_id);
    let read =
        ReadBuilder::new().filter(filter).sign(bob).build().await.expect("should find write");
    let reply = node.request(read).owner(bob.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let Some(mut data_stream) = read_reply.entry.data else {
        panic!("should have data");
    };

    let mut buffer = Vec::new();
    data_stream.read_to_end(&mut buffer).expect("should read to end");
    assert_eq!(buffer, data);
}

// Should return a status of NotFound (404) when deleting a non-existent record.
#[tokio::test]
async fn not_found() {
    let node = node().await;
    let alice = alice().await;

    let delete = DeleteBuilder::new()
        .record_id("imaginary_record_id")
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::NotFound(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record found");
}

// Should disallow delete when there is a newer record.
#[tokio::test]
async fn newer_version() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let data = br#"{"record": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice updates the initial write's data.
    // --------------------------------------------------
    let data = br#"{"record": "test record write again"}"#;

    let write = WriteBuilder::from(write.clone())
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to delete the initial write but fails.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    // fake older timestamp
    let timestamp = write.descriptor.base.message_timestamp;
    delete.descriptor.base.message_timestamp =
        timestamp.checked_sub_days(Days::new(1)).expect("should subtract days");

    let Err(Error::Conflict(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be Conflict");
    };
    assert_eq!(e, "newer record version exists");
}

// Should be able to delete and then rewrite the same data.
#[tokio::test]
async fn rewrite_data() {
    let node = node().await;
    let alice = alice().await;

    let data = br#"{"record": "test record write"}"#;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");
    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes another record with the same data.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow delete using the 'allow-anyone' rule.
#[tokio::test]
async fn anyone_delete() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let allow_any = include_bytes!("../examples/protocols/anyone-collaborate.json");
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
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob (or anyone else) successfully deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow recipient to delete using an ancestor recipient rule.
#[tokio::test]
async fn ancestor_recipient() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let recipient_can = include_bytes!("../examples/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient_can).expect("should deserialize");

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
    // Alice writes a chat record with Bob as the recipient.
    // --------------------------------------------------
    let data = br#"{"record": "chat write"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(tag.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete the chat/tag.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&tag.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as recipient) is able to delete the chat/tag.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&tag.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow recipient to delete using a recipient rule.
#[tokio::test]
async fn direct_recipient() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let recipient_can = include_bytes!("../examples/protocols/recipient-can.json");
    let definition: Definition = serde_json::from_slice(recipient_can).expect("should deserialize");

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
    // Alice writes a chat record with Bob as the recipient.
    // --------------------------------------------------
    let data = br#"{"record": "chat write"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete the chat record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as recipient) is able to delete the chat record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow the author to delete with ancestor author rule.
#[tokio::test]
async fn ancestor_author() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
    // --------------------------------------------------
    let author_can = include_bytes!("../examples/protocols/author-can.json");
    let definition: Definition = serde_json::from_slice(author_can).expect("should deserialize");

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
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(post.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

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
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = node.request(comment.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's 'post/comment'.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&comment.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as post author) is able to delete the post comment.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&comment.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow co-delete by invoking a context role.
#[tokio::test]
async fn context_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
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
    // Alice creates a thread.
    // --------------------------------------------------
    let data = br#"{"record": "thread write"}"#;

    let thread = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
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
    // Alice adds Bob as a 'thread/admin' for the thread
    // --------------------------------------------------
    let data = br#"{"record": "Bob admin"}"#;

    let admin = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "thread/admin",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(admin.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message on the thread
    // --------------------------------------------------
    let data = br#"{"record": "chat message"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's 'post/comment'.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as thread admin) is able to delete the chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .protocol_role("thread/admin")
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should allow co-delete by invoking a root-level role.
#[tokio::test]
async fn root_role() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures a protocol.
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
    // Alice adds Bob as a 'thread/admin' at root level.
    // --------------------------------------------------
    let data = br#"{"record": "Bob admin"}"#;

    let admin = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(bob.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "admin",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(admin.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message.
    // --------------------------------------------------
    let data = br#"{"record": "a chat message"}"#;

    let chat = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .recipient(alice.did())
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(chat.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol is unable to delete Alice's chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .sign(carol)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");

    // --------------------------------------------------
    // Bob (as admin) is able to delete the chat message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&chat.record_id)
        .protocol_role("admin")
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

// Should return a status of Forbidden (403) if message is not authorized.
#[tokio::test]
async fn forbidden() {
    let node = node().await;
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");

    let Err(Error::Forbidden(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "delete request failed authorization");
}

// Should return a status of Forbidden (403) if message is not authorized.
#[tokio::test]
async fn unauthorized() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id("record_id")
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    delete.authorization.signature.signatures[0].signature = "bad_signature".to_string();

    let Err(Error::Unauthorized(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be Unauthorized");
    };
    assert!(e.starts_with("failed to authenticate"));
}

// Should return a status of BadRequest (400) when message is invalid.
#[tokio::test]
async fn invalid_message() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Bob attempts to delete the record but is unable to.
    // --------------------------------------------------
    let mut delete = DeleteBuilder::new()
        .record_id("record_id")
        .sign(alice)
        .build()
        .await
        .expect("should create delete");
    delete.descriptor = DeleteDescriptor::default();

    let Err(Error::BadRequest(e)) = node.request(delete).owner(alice.did()).await else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}

// Should index additional properties for the record being deleted.
#[tokio::test]
async fn index_additional() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .schema("http://test_schema")
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check MessageStore and EventLog.
    // --------------------------------------------------
    let query = store::RecordsQueryBuilder::new()
        .add_filter(RecordsFilter::new().schema("http://test_schema"))
        .method(Some(Method::Delete))
        .include_archived(true)
        .build();

    let (entries, _) = MessageStore::query(&node.provider, alice.did(), &query.clone().into())
        .await
        .expect("should query");
    assert_eq!(entries.len(), 1);

    // check log
    let (entries, _) =
        MessageStore::query(&node.provider, alice.did(), &query).await.expect("should query");
    assert_eq!(entries.len(), 1);
}

// Should log delete event while retaining initial write event.
#[tokio::test]
async fn log_delete() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete.clone()).owner(alice.did()).await.expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check EventLog.
    // --------------------------------------------------
    let query = messages::QueryBuilder::new()
        .add_filter(MessagesFilter::new().interface(Interface::Records))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let query = store::Query::from(query);

    let (entries, _) =
        EventLog::query(&node.provider, alice.did(), &query).await.expect("should query");
    assert_eq!(entries.len(), 2);
}

// Should delete all writes except the initial write.
#[tokio::test]
async fn delete_updates() {
    let node = node().await;
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes record.
    // --------------------------------------------------
    let data = br#"{"record": "a record"}"#;

    let write1 = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write1.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write2 = WriteBuilder::from(write1.clone())
        .data(Data::from(data.to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let reply = node.request(write2.clone()).owner(alice.did()).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice deletes the message.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write2.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    let reply = node.request(delete.clone()).owner(alice.did()).await.expect("should delete");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Check EventLog. There should only be 2 events: the initial write and the delete.
    // --------------------------------------------------
    let query = messages::QueryBuilder::new()
        .add_filter(MessagesFilter::new().interface(Interface::Records))
        .sign(alice)
        .build()
        .await
        .expect("should create query");
    let query = store::Query::from(query);

    let (entries, _) =
        EventLog::query(&node.provider, alice.did(), &query).await.expect("should query");
    assert_eq!(entries.len(), 2);
}
