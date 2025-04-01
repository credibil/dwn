//! Client
//!
//! This test demonstrates how a web node owner create messages and
//! subsequently query for them.

#![cfg(feature = "client")]

#[path = "../examples/kms/mod.rs"]
mod kms;
#[path = "../examples/provider/mod.rs"]
mod provider;

use std::io::Cursor;
use std::sync::LazyLock;

use credibil_dwn::Method;
use credibil_dwn::client::grants::{GrantBuilder, Scope};
use credibil_dwn::client::messages::{QueryBuilder, ReadBuilder};
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{Data, ProtocolBuilder, WriteBuilder};
use kms::Keyring;

static ALICE: LazyLock<Keyring> = LazyLock::new(Keyring::new);
static BOB: LazyLock<Keyring> = LazyLock::new(Keyring::new);

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn configure_builder() {
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&*ALICE)
        .build()
        .await
        .expect("should build");

    assert_eq!(configure.descriptor.definition.protocol, definition.protocol);
}

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn write_builder() {
    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let write = WriteBuilder::new()
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema(definition.types["post"].schema.as_ref().unwrap())
        .data(Data::Stream(Cursor::new(br#"{"message": "test record write"}"#.to_vec())))
        .published(true)
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create write");

    assert_eq!(write.descriptor.protocol, Some(definition.protocol));
}

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn query_builder() {
    let query = QueryBuilder::new().sign(&*ALICE).build().await.expect("should create query");
    assert!(query.descriptor.filters.is_empty());
}

// Should fetch all messages for owner owner beyond a provided cursor.
#[tokio::test]
async fn read() {
    let read = ReadBuilder::new()
        .message_cid("bafkreidmebcej4sqoz6lolq3zuyd6ijs7ciouylornny3y5sdx7tiuegwm")
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create read");

    assert_eq!(
        read.descriptor.message_cid,
        "bafkreidmebcej4sqoz6lolq3zuyd6ijs7ciouylornny3y5sdx7tiuegwm"
    );
}

// Should allow querying of messages with matching interface and method grant scope.
#[tokio::test]
async fn grant_builder() {
    let grant = GrantBuilder::new()
        .granted_to(&BOB.did)
        .scope(Scope::Messages {
            method: Method::Query,
            protocol: None,
        })
        .sign(&*ALICE)
        .build()
        .await
        .expect("should create grant");

    assert_eq!(
        grant.descriptor.protocol,
        Some("https://credibil.website/dwn/permissions".to_string())
    );
}
