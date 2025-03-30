//! DWN Client Example
//!
//! This example demonstrates a DWN client interacting with a Decentralized Web
//! Node (DWN).

mod keystore;

use std::io::Cursor;

use credibil_dwn::client::protocols::{ConfigureBuilder, Definition};
use credibil_dwn::client::records::{Data, ProtocolBuilder, WriteBuilder};
use http::StatusCode;

#[tokio::main]
async fn main() {
    let alice = keystore::new_keyring();

    let allow_any = include_bytes!("../examples/protocols/allow-any.json");
    let definition: Definition = serde_json::from_slice(allow_any).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(&alice)
        .build()
        .await
        .expect("should build");

    let response = reqwest::Client::new()
        .post(format!("http://0.0.0.0:8080/{}", alice.did()))
        // .header("Content-Type", "application/json")
        // .header("Accept", "application/json")
        .json(&configure)
        .send()
        .await
        .expect("should send");

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let data = br#"{"message": "test record write"}"#;
    let reader = Cursor::new(data.to_vec());
    let schema = definition.types["post"].schema.clone().expect("should have schema");

    let write = WriteBuilder::new()
        .protocol(ProtocolBuilder {
            protocol: &definition.protocol,
            protocol_path: "post",
            parent_context_id: None,
        })
        .schema(&schema)
        .data(Data::Stream(reader.clone()))
        .published(true)
        .sign(&alice)
        .build()
        .await
        .expect("should create write");

    let response = reqwest::Client::new()
        .post(format!("http://0.0.0.0:8080/{}", alice.did()))
        // .header("Content-Type", "application/json")
        // .header("Accept", "application/json")
        .json(&write)
        .send()
        .await
        .expect("should send");

    // assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = response.json().await.expect("should deserialize");
    println!("Body: {body}");
}
