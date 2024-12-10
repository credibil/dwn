//! Records Read

use dwn_test::key_store::ALICE_DID;
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_dwn::data::DataStream;
use vercre_dwn::endpoint;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{ReadBuilder, RecordsFilter, WriteBuilder, WriteData};

// The owner should be able to read their own records.
#[tokio::test]
async fn owner_records() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .signer(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let record_id = write.record_id.clone();

    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(record_id))
        .build(&alice_keyring)
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let record = body.entry.records_write.expect("should have records_write");

    assert_snapshot!("read", record, {
        ".recordId" => "[recordId]",
        ".descriptor.messageTimestamp" => "[messageTimestamp]",
        ".descriptor.dateCreated" => "[dateCreated]",
        ".authorization.signature.payload" => "[payload]",
        ".authorization.signature.signatures[0].signature" => "[signature]",
        ".attestation.payload" => "[payload]",
        ".attestation.signatures[0].signature" => "[signature]",
    });
}
