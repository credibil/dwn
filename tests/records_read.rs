//! Records Read

use dwn_test::key_store::{ALICE_DID, BOB_DID, CAROL_DID};
use dwn_test::provider::ProviderImpl;
use http::StatusCode;
use serde_json::Value;
use vercre_dwn::data::DataStream;
use vercre_dwn::protocols::{ConfigureBuilder, Definition};
use vercre_dwn::provider::{KeyStore, MessageStore};
use vercre_dwn::records::{
    DeleteBuilder, ReadBuilder, RecordsFilter, WriteBuilder, WriteData, WriteProtocol,
};
use vercre_dwn::store::Entry;
use vercre_dwn::{Error, endpoint};

// Should allow an owner to read their own records.
#[tokio::test]
async fn owner() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec().to_vec())))
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
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec().to_vec())))
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
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec().to_vec())))
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
    assert!(body.entry.records_write.is_some());
}

// Should allow authenticated users to read published records.
#[tokio::test]
async fn published_authenticated() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec().to_vec())))
        .published(true)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
}

// Should allow non-owners to read records they have received.
#[tokio::test]
async fn non_owner_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .recipient(BOB_DID)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
}

// Should return BadRequest (400) when attempting to fetch a deleted record
// using a valid `record_id`.
#[tokio::test]
async fn deleted_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Mock write and delete, saving only the `RecordsDelete`.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .recipient(BOB_DID)
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");

    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&alice_keyring)
        .await
        .expect("should create delete");

    let mut initial = Entry::from(&write);
    initial.indexes.insert("recordId".to_string(), Value::String(write.record_id.clone()));
    let mut entry = Entry::from(&delete);
    entry.indexes.extend(initial.indexes);

    MessageStore::put(&provider, ALICE_DID, &entry).await.expect("should save");

    // --------------------------------------------------
    // Alice attempts to read the record and gets an error.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::BadRequest(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "initial write for deleted record not found");
}

// Should return Forbidden (403) when non-authors attempt to fetch the initial
// write of a deleted record using a valid `record_id`.
#[tokio::test]
async fn non_author_deleted_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol allowing anyone to write.
    // --------------------------------------------------
    let def_json = serde_json::json!({
        "published" : true,
        "protocol"  : "https://example.com/foo",
        "types"     : {
            "foo": {}
        },
        "structure": {
            "foo": {
                "$actions": [{
                    "who" : "anyone",
                    "can" : ["create", "delete"]
                }]
            }
        }
    });
    let definition: Definition = serde_json::from_value(def_json).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record to Alice's web node.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .protocol(WriteProtocol {
            protocol: "https://example.com/foo".to_string(),
            protocol_path: "foo".to_string(),
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .build(&bob_keyring)
        .await
        .expect("should create delete");
    let reply = endpoint::handle(ALICE_DID, delete, &provider).await.expect("should read");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol attempts to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow non-owners to read records they have authored.
#[tokio::test]
async fn non_owner_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");
    let carol_keyring = provider.keyring(CAROL_DID).expect("should get Carol's keyring");

    // --------------------------------------------------
    // Alice configures a protocol allowing anyone to write.
    // --------------------------------------------------
    let def_json = serde_json::json!({
        "published" : true,
        "protocol"  : "https://example.com/foo",
        "types"     : {
            "foo": {}
        },
        "structure": {
            "foo": {
                "$actions": [{
                    "who" : "anyone",
                    "can" : ["create"]
                }]
            }
        }
    });
    let definition: Definition = serde_json::from_value(def_json).expect("should deserialize");

    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record to Alice's web node.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .protocol(WriteProtocol {
            protocol: "https://example.com/foo".to_string(),
            protocol_path: "foo".to_string(),
        })
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads his record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());

    // --------------------------------------------------
    // Carol attempts to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&carol_keyring)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should include intial write for updated records.
#[tokio::test]
async fn initial_write_included() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice writes a record and then an update.
    // --------------------------------------------------
    let write_1 = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_1.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    let write_2 = WriteBuilder::from(write_1)
        .data(WriteData::Reader(DataStream::from(b"some data".to_vec())))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply =
        endpoint::handle(ALICE_DID, write_2.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads her record which includes the `initial_write`.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write_2.record_id))
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.initial_write.is_some());
}

// Should allow anyone to read when using `allow-anyone` rule.
#[tokio::test]
async fn allow_anyone() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bob's keyring");

    // --------------------------------------------------
    // Alice configures a social media protocol.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice saves an image.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"cafe-aesthetic.jpg".to_vec())))
        .protocol(WriteProtocol {
            protocol: "http://social-media.xyz".to_string(),
            protocol_path: "image".to_string(),
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the image.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&bob_keyring)
        .build()
        .await
        .expect("should create read");
    let reply = endpoint::handle(ALICE_DID, read.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::OK);

    let body = reply.body.expect("should have body");
    assert!(body.entry.records_write.is_some());
}

// Should not allow anonymous reads when there is no `allow-anyone` rule.
#[tokio::test]
async fn no_anonymous() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");

    // --------------------------------------------------
    // Alice configures a social media protocol.
    // --------------------------------------------------
    let social_media = include_bytes!("../crates/dwn-test/protocols/email.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .build(&alice_keyring)
        .await
        .expect("should build");
    let reply =
        endpoint::handle(ALICE_DID, configure, &provider).await.expect("should configure protocol");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a message.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(WriteData::Reader(DataStream::from(b"foo".to_vec())))
        .protocol(WriteProtocol {
            protocol: "http://email-protocol.xyz".to_string(),
            protocol_path: "email".to_string(),
        })
        .schema("email")
        .data_format("text/plain")
        .sign(&alice_keyring)
        .build()
        .await
        .expect("should create write");
    let reply = endpoint::handle(ALICE_DID, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status.code, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // An anonymous users attempts to read the message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .build()
        .expect("should create read");
    let Err(Error::Forbidden(e)) = endpoint::handle(ALICE_DID, read, &provider).await else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "read not authorized");
}

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
