//! Records Read

use dwn_test::key_store::{ALICE_DID, BOB_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use vercre_dwn::data::DataStream;
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{ReadBuilder, RecordsFilter, WriteBuilder, WriteData};
use vercre_dwn::{Error, endpoint};

// Should allow an owner to read their own records.
#[tokio::test]
async fn owner() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let record = body.entry.records_write.expect("should have records_write");
    assert_eq!(record.record_id, write.record_id);
}

// Should not allow non-owners to read private records.
#[tokio::test]
async fn disallow_non_owner() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;

    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "read cannot be authorized");
}

// Should allow anonymous users to read published records.
#[tokio::test]
async fn published_anonymous() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let data = br#"{"message": "test record write"}"#;
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(data.to_vec())))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .build()
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read, &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let record = body.entry.records_write.expect("should have records_write");
    assert_eq!(record.record_id, write.record_id);
}

// // Should allow authenticated users to read published records.
// #[tokio::test]
// async fn published_authenticated() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow non-owners to read records they have received.
// #[tokio::test]
// async fn non_owner_recipient() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return BadRequest (400) when attempting to fetch the initial write of a deleted record.
// #[tokio::test]
// async fn deleted_write() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return Forbidden (403) when non-authors attempt to fetch the initial
// // write of a deleted record.
// #[tokio::test]
// async fn non_author_deleted_write() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow non-owners to read records they have authored.
// #[tokio::test]
// async fn non_owner_author() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should include intial write for updated records.
// #[tokio::test]
// async fn include_initial_write() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow anyone to read when using `allow-anyone` rule.
// #[tokio::test]
// async fn allow_anyone() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow anonymous reads when there is no `allow-anyone` rule.
// #[tokio::test]
// async fn anonymous_no_allow_anyone() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow read using ancestor recipient rule.
// #[tokio::test]
// async fn ancestor_recipient() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow read using ancestor author rule.
// #[tokio::test]
// async fn ancestor_author() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should support using a filter when there is only a single result.
// #[tokio::test]
// async fn filter_single() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return an exception when using a filter returns multiple results.
// #[tokio::test]
// async fn filter_many() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow using a root-level role to authorize reads.
// #[tokio::test]
// async fn root_role() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reads when protocol path does not point to an active role record.
// #[tokio::test]
// async fn incorrect_protocol_path() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reads when recipient does not have an active role.
// #[tokio::test]
// async fn no_recipient_role() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow reads when using a valid context role.
// #[tokio::test]
// async fn context_role() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reads when context role is used in wrong context.
// #[tokio::test]
// async fn incorrect_context_role() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should disallow external party reads when grant has incorrect method scope.
// #[tokio::test]
// async fn incorrect_grant_method() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow reads of protocol records using grants with unrestricted scope.
// #[tokio::test]
// async fn unrestricted_grant() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow reads of protocol records with matching grant scope.
// #[tokio::test]
// async fn grant_protocol() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reads when grant scope does not match record protocol scope.
// #[tokio::test]
// async fn incorrect_grant_protocol() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow reading records within the context specified by the grant.
// #[tokio::test]
// async fn grant_context() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reading records within when grant context does not match.
// #[tokio::test]
// async fn incorrect_grant_context() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should allow reading records in the grant protocol path.
// #[tokio::test]
// async fn grant_protocol_path() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not allow reading records outside the grant protocol path.
// #[tokio::test]
// async fn no_grant_protocol_path() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return NotFound (404) when record does not exist.
// #[tokio::test]
// async fn record_not_found() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return NotFound (404) when record has been deleted.
// #[tokio::test]
// async fn record_deleted() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return NotFound (404) when record data blocks have been deleted.
// #[tokio::test]
// async fn data_blocks_deleted() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should not get data from block store when record has `encoded_data`.
// #[tokio::test]
// async fn encoded_data() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should get data from block store when record does not have `encoded_data`.
// #[tokio::test]
// async fn no_encoded_data() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should decrypt flat-space schema-contained records using a derived key.
// #[tokio::test]
// async fn decrypt_schema() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should decrypt flat-space schemaless records using a derived key.
// #[tokio::test]
// async fn decrypt_schemaless() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should only be able to decrypt records using the correct derived private key
// // within a protocol-context derivation scheme.
// #[tokio::test]
// async fn decrypt_context() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should only be able to decrypt records using the correct derived private key
// // within a protocol derivation scheme.
// #[tokio::test]
// async fn decrypt_protocol() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return Unauthorized (401) for invalid signatures.
// #[tokio::test]
// async fn invalid_signature() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }

// // Should return BadRequest (400) for unparsable messages.
// #[tokio::test]
// async fn invalid_message() {
//     let provider = ProviderImpl::new().await.expect("should create provider");
//     let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
// }
