//! Messages Subscribe

use std::time::Duration;

use dwn_node::interfaces::records::{
    Data, QueryBuilder, RecordsFilter, SubscribeBuilder, WriteBuilder,
};
use dwn_node::{Message, StatusCode, endpoint};
use futures::StreamExt;
use test_node::key_store;
use test_node::provider::ProviderImpl;
use tokio::time;

// The owner should be able to subscribe their own event stream.
#[tokio::test]
async fn owner_events() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = key_store::new_keyring();

    // --------------------------------------------------
    // Alice subscribes to own event stream.
    // --------------------------------------------------
    let filter = RecordsFilter::new().add_author(&alice.did);
    let subscribe = SubscribeBuilder::new()
        .filter(filter)
        .sign(&alice)
        .build()
        .await
        .expect("should build");
    let reply =
        endpoint::handle(&alice.did, subscribe, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::OK);
    let mut subscribe_reply = reply.body.expect("should have body");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .sign(&alice)
        .build()
        .await
        .expect("should create write");

    let message_cid = write.cid().expect("should have cid");

    let reply = endpoint::handle(&alice.did, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Ensure the RecordsWrite event exists.
    // --------------------------------------------------
    let filter = RecordsFilter::new().record_id(&write.record_id);
    let query = QueryBuilder::new()
        .filter(filter)
        .sign(&alice)
        .build()
        .await
        .expect("should create query");
    let reply = endpoint::handle(&alice.did, query, &provider).await.expect("should query");
    assert_eq!(reply.status.code, StatusCode::OK);

    let query_reply = reply.body.expect("should have reply");
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    // assert_eq!(entries[0], message_cid);

    // --------------------------------------------------
    // The subscriber should have a matching write event.
    // --------------------------------------------------
    let find_event = async move {
        while let Some(event) = subscribe_reply.subscription.next().await {
            if message_cid == event.cid().unwrap() {
                break;
            }
        }
    };
    if let Err(_) = time::timeout(Duration::from_millis(500), find_event).await {
        panic!("should have found event");
    }
}
