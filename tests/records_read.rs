//! Records Read

#![cfg(all(feature = "client", feature = "server"))]

#[path = "../examples/kms/mod.rs"]
mod kms;
#[path = "../examples/provider/mod.rs"]
mod provider;

use std::io::{Cursor, Read};

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_dwn::client::grants::{GrantBuilder, RecordsScope, Scope};
use credibil_dwn::client::protocols::{ConfigureBuilder, Definition, QueryBuilder};
use credibil_dwn::client::records::{
    Data, DeleteBuilder, EncryptOptions, ProtocolBuilder, ReadBuilder, Recipient, RecordsFilter,
    WriteBuilder, decrypt,
};
use credibil_dwn::hd_key::{
    self, DerivationPath, DerivationScheme, DerivedPrivateJwk, PrivateKeyJwk,
};
use credibil_dwn::interfaces::protocols::QueryReply;
use credibil_dwn::interfaces::records::ReadReply;
use credibil_dwn::provider::{DataStore, MessageStore};
use credibil_dwn::store::{MAX_ENCODED_SIZE, Storable};
use credibil_dwn::{Error, Method, StatusCode, cid};
use credibil_identity::{Key, SignerExt};
use credibil_jose::PublicKeyJwk;
use credibil_se::{Curve, KeyType};
use kms::Keyring;
use provider::ProviderImpl;
use rand::RngCore;
use tokio::sync::OnceCell;

static ALICE: OnceCell<Keyring> = OnceCell::const_new();
static BOB: OnceCell<Keyring> = OnceCell::const_new();
static CAROL: OnceCell<Keyring> = OnceCell::const_new();

async fn alice() -> &'static Keyring {
    ALICE
        .get_or_init(|| async {
            let keyring = Keyring::new("records_read_alice").await.expect("create keyring");
            keyring
        })
        .await
}

async fn bob() -> &'static Keyring {
    BOB.get_or_init(|| async {
        let keyring = Keyring::new("records_read_bob").await.expect("create keyring");
        keyring
    })
    .await
}

async fn carol() -> &'static Keyring {
    CAROL
        .get_or_init(|| async {
            let keyring = Keyring::new("records_read_carol").await.expect("create keyring");
            keyring
        })
        .await
}

// Should allow an owner to read their own records.
#[tokio::test]
async fn owner() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let record = read_reply.entry.records_write.expect("should have records_write");
    assert_eq!(record.record_id, write.record_id);
}

// Should not allow non-owners to read private records.
#[tokio::test]
async fn disallow_non_owner() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record but fails.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "read cannot be authorized");
}

// Should allow anonymous users to read published records.
#[tokio::test]
async fn published_anonymous() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Add a `write` record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new().filter(RecordsFilter::new().record_id(&write.record_id)).build();
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
}

// Should allow authenticated users to read published records.
#[tokio::test]
async fn published_authenticated() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
}

// Should allow non-owners to read records they have received.
#[tokio::test]
async fn non_owner_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
}

// Should return BadRequest (400) when attempting to fetch a deleted record
// using a valid `record_id`.
#[tokio::test]
async fn deleted_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Mock write and delete, saving only the `RecordsDelete`.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .sign(alice)
        .build()
        .await
        .expect("should create write");

    let mut delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");

    for (key, value) in write.indexes() {
        delete.add_index(key, value);
    }
    MessageStore::put(&provider, &alice.did().await.expect("did"), &delete)
        .await
        .expect("should save");

    // --------------------------------------------------
    // Alice attempts to read the record and gets an error.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let Err(Error::BadRequest(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "initial write for deleted record not found");
}

// Should return Forbidden (403) when non-authors attempt to fetch the initial
// write of a deleted record using a valid `record_id`.
#[tokio::test]
async fn non_author_deleted_write() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

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
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record to Alice's web node.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "https://example.com/foo",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob deletes the record.
    // --------------------------------------------------
    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create delete");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), delete, &provider)
        .await
        .expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Carol attempts to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(carol)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow non-owners to read records they have authored.
#[tokio::test]
async fn non_owner_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

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
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes a record to Alice's web node.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "https://example.com/foo",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads his record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());

    // --------------------------------------------------
    // Carol attempts to read the record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(carol)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should include intial write for updated records.
#[tokio::test]
async fn initial_write_included() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record and then an update.
    // --------------------------------------------------
    let write_1 = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write_1.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let write_2 = WriteBuilder::from(write_1)
        .data(Data::from(b"some data".to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write_2.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads her record which includes the `initial_write`.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write_2.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.initial_write.is_some());
}

// Should allow anyone to read when using `allow-anyone` rule.
#[tokio::test]
async fn allow_anyone() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a social media protocol.
    // --------------------------------------------------
    let social_media = include_bytes!("../examples/protocols/social-media.json");
    let definition: Definition = serde_json::from_slice(social_media).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice saves an image.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"cafe-aesthetic.jpg".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://social-media.xyz",
            protocol_path: "image",
            parent_context_id: None,
        })
        .schema("imageSchema")
        .data_format("image/jpeg")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the image.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
}

// Should not allow anonymous reads when there is no `allow-anyone` rule.
#[tokio::test]
async fn no_anonymous() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../examples/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an email.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"foo".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // An anonymous users attempts to read the message.
    // --------------------------------------------------
    let read = ReadBuilder::new().filter(RecordsFilter::new().record_id(&write.record_id)).build();
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "read not authorized");
}

// Should allow read using recipient rule.
#[tokio::test]
async fn allow_recipient() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../examples/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes an email to BOB.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"Hello Bob!".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the email.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());

    // --------------------------------------------------
    // Carol attempts to read the email.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(carol)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should allow read using ancestor author rule.
#[tokio::test]
async fn allow_author() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;
    let carol = carol().await;

    // --------------------------------------------------
    // Alice configures an email protocol.
    // --------------------------------------------------
    let email = include_bytes!("../examples/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob writes an email to ALICE.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"Hello Alice!".to_vec()))
        .recipient(&alice.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .sign(bob)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads his email.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());

    // --------------------------------------------------
    // Carol attempts to read the email.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(carol)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "action not permitted");
}

// Should support using a filter when there is only a single result.
#[tokio::test]
async fn filter_one() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures a nested protocol.
    // --------------------------------------------------
    let nested = include_bytes!("../examples/protocols/nested.json");
    let definition: Definition = serde_json::from_slice(nested).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a message to a nested protocol.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"foo".to_vec()))
        .recipient(&alice.did().await.expect("did"))
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
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().protocol("http://nested.xyz").protocol_path("foo"))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
}

// Should return a status of BadRequest (400) when using a filter returns multiple results.
#[tokio::test]
async fn filter_many() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice configures a nested protocol.
    // --------------------------------------------------
    let nested = include_bytes!("../examples/protocols/nested.json");
    let definition: Definition = serde_json::from_slice(nested).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 messages to a nested protocol.
    // --------------------------------------------------
    for _ in 0..2 {
        let write = WriteBuilder::new()
            .data(Data::from(b"foo".to_vec()))
            .recipient(&alice.did().await.expect("did"))
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
        let reply =
            credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
                .await
                .expect("should write");
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }

    // --------------------------------------------------
    // Alice attempts to read one of the messages.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().protocol("http://nested.xyz").protocol_path("foo"))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let Err(Error::BadRequest(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert_eq!(e, "multiple messages exist");
}

// Should allow using a root-level role to authorize reads.
#[tokio::test]
async fn root_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes 2 messages to the protocol.
    // --------------------------------------------------
    let bob_friend = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "friend",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_friend.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let chat = WriteBuilder::new()
        .data(Data::from(b"Bob can read this because he is a friend".to_vec()))
        .recipient(&alice.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), chat.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads Alice's chat message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(chat.record_id))
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should not allow reads when protocol path does not point to an active role record.
#[tokio::test]
async fn invalid_protocol_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message to the protocol.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Blah blah blah".to_vec()))
        .recipient(&alice.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), chat.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read Alice's chat message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(chat.record_id))
        .protocol_role("chat")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "protocol path does not match role record type");
}

// Should not allow reads when recipient does not have an active role.
#[tokio::test]
async fn no_recipient_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a friend protocol.
    // --------------------------------------------------
    let friend = include_bytes!("../examples/protocols/friend-role.json");
    let definition: Definition = serde_json::from_slice(friend).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message to the protocol.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Blah blah blah".to_vec()))
        .recipient(&alice.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://friend-role.xyz",
            protocol_path: "chat",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), chat.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read Alice's chat message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(chat.record_id))
        .protocol_role("friend")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should allow reads when using a valid context role.
#[tokio::test]
async fn context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a thread protocol.
    // --------------------------------------------------
    let thread = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates a thread.
    // --------------------------------------------------
    let thread = WriteBuilder::new()
        .data(Data::from(b"A new thread".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), thread.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a participant on the thread.
    // --------------------------------------------------
    let participant = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(&bob.did().await.expect("did"))
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
        credibil_dwn::handle(&alice.did().await.expect("did"), participant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message on the thread.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Bob can read this because he is a participant".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), chat.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads his participant role record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(
            RecordsFilter::new()
                .protocol_path("thread/participant")
                .add_recipient(&bob.did().await.expect("did"))
                .context_id(thread.context_id.as_ref().unwrap()),
        )
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);

    // --------------------------------------------------
    // Bob reads the thread root record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(participant.descriptor.parent_id.as_ref().unwrap()))
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);

    // --------------------------------------------------
    // Bob uses his participant role to read the chat message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(chat.record_id))
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should not allow reads when context role is used in wrong context.
#[tokio::test]
async fn invalid_context_role() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a thread protocol.
    // --------------------------------------------------
    let thread = include_bytes!("../examples/protocols/thread-role.json");
    let definition: Definition = serde_json::from_slice(thread).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice creates 2 threads.
    // --------------------------------------------------
    let thread_1 = WriteBuilder::new()
        .data(Data::from(b"Thread 1".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), thread_1.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let thread_2 = WriteBuilder::new()
        .data(Data::from(b"Thread 2".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), thread_2.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice adds Bob as a participant on the thread.
    // --------------------------------------------------
    let participant = WriteBuilder::new()
        .data(Data::from(b"Bob is a friend".to_vec()))
        .recipient(&bob.did().await.expect("did"))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/participant",
            parent_context_id: thread_1.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), participant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a chat message to thread 2.
    // --------------------------------------------------
    let chat = WriteBuilder::new()
        .data(Data::from(b"Bob can read this because he is a participant".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://thread-role.xyz",
            protocol_path: "thread/chat",
            parent_context_id: thread_2.context_id.clone(),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), chat.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob uses his participant role to read the chat message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(chat.record_id))
        .protocol_role("thread/participant")
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "unable to find record for role");
}

// Should disallow external party reads when grant has incorrect method scope.
#[tokio::test]
async fn invalid_grant_method() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"Bob can read this because I have granted him permission".to_vec()))
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to write (not read) records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "https://example.com/protocol/test".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read his participant role record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "method is not within grant scope");
}

// Should allow reads of protocol records using grants with unrestricted scope.
#[tokio::test]
async fn unrestricted_grant() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record without using the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no rule defined for action");

    // --------------------------------------------------
    // Bob reads the record using the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should allow reads of protocol records with matching grant scope.
#[tokio::test]
async fn grant_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ProtocolPath("foo".to_string())),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record without using the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "no rule defined for action");

    // --------------------------------------------------
    // Bob reads the record using the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should not allow reads when grant scope does not match record protocol scope.
#[tokio::test]
async fn invalid_grant_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://a-different-protocol.com".to_string(),
            limited_to: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record using the mismatching grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "scope protocol does not match write protocol");
}

// Should allow reading records within the context specified by the grant.
#[tokio::test]
async fn grant_context() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ContextId(write.context_id.clone().unwrap())),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads the record using the grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should not allow reading records within when grant context does not match.
#[tokio::test]
async fn invalid_grant_context() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ContextId("somerandomgrant".to_string())),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record using the mismatching grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "record not part of grant context");
}

// Should allow reading records in the grant protocol path.
#[tokio::test]
async fn grant_protocol_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ProtocolPath("foo".to_string())),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record using the mismatching grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should not allow reading records outside the grant protocol path.
#[tokio::test]
async fn invalid_grant_protocol_path() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice configures a minimal protocol.
    // --------------------------------------------------
    let minimal = include_bytes!("../examples/protocols/minimal.json");
    let definition: Definition = serde_json::from_slice(minimal).expect("should deserialize");
    let configure = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice writes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"minimal".to_vec()))
        .protocol(ProtocolBuilder {
            protocol: "http://minimal.xyz",
            protocol_path: "foo",
            parent_context_id: None,
        })
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice grants Bob permission to read records.
    // --------------------------------------------------
    let bob_grant = GrantBuilder::new()
        .granted_to(&bob.did().await.expect("did"))
        .scope(Scope::Records {
            method: Method::Read,
            protocol: "http://minimal.xyz".to_string(),
            limited_to: Some(RecordsScope::ProtocolPath("different-protocol-path".to_string())),
        })
        .sign(alice)
        .build()
        .await
        .expect("should create grant");
    let reply =
        credibil_dwn::handle(&alice.did().await.expect("did"), bob_grant.clone(), &provider)
            .await
            .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob attempts to read the record using the mismatching grant.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(write.record_id))
        .permission_grant_id(bob_grant.record_id)
        .sign(bob)
        .build()
        .await
        .expect("should create read");
    let Err(Error::Forbidden(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Forbidden");
    };
    assert_eq!(e, "grant and record protocol paths do not match");
}

// Should return a status of NotFound (404) when record does not exist.
#[tokio::test]
async fn record_not_found() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id("non-existent-record".to_string()))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let Err(Error::NotFound(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "no matching record");
}

// Should return NotFound (404) when record has been deleted.
#[tokio::test]
async fn record_deleted() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes then  deletes a record.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"some data".to_vec()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let delete = DeleteBuilder::new()
        .record_id(&write.record_id)
        .sign(alice)
        .build()
        .await
        .expect("should create delete");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), delete, &provider)
        .await
        .expect("should read");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice attempts to read the deleted record.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    // TODO: convert to a NotFound error.
    // let Err(Error::NotFound(e)) = endpoint::handle(&alice.did().await.expect("did"), read, &provider).await else {
    //     panic!("should be NotFound");
    // };
    // assert_eq!(e, "no matching record");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

// Should return NotFound (404) when record data blocks have been deleted.
#[tokio::test]
async fn data_blocks_deleted() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record and then deletes its data from BlockStore.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);

    let write = WriteBuilder::new()
        .data(Data::from(data.to_vec()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // delete record's data
    DataStore::delete(
        &provider,
        &alice.did().await.expect("did"),
        &write.record_id,
        &write.descriptor.data_cid,
    )
    .await
    .expect("should delete block");

    // --------------------------------------------------
    // Alice attempts to read the record with deleted data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let Err(Error::NotFound(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be NotFound");
    };
    assert_eq!(e, "data not found");
}

// Should not get data from block store when record has `encoded_data`.
#[tokio::test]
async fn encoded_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record and then deletes data from BlockStore.
    // --------------------------------------------------
    let write = WriteBuilder::new()
        .data(Data::from(b"data small enough to be encoded".to_vec()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // deleting BlockStore data has no effect as the record uses encoded data
    DataStore::delete(
        &provider,
        &alice.did().await.expect("did"),
        &write.record_id,
        &write.descriptor.data_cid,
    )
    .await
    .expect("should delete block");

    // --------------------------------------------------
    // Alice reads the record with encoded data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::OK);
}

// Should get data from block store when record does not have `encoded_data`.
#[tokio::test]
async fn block_data() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice writes a record and then deletes its data from BlockStore.
    // --------------------------------------------------
    let mut data = [0u8; MAX_ENCODED_SIZE + 10];
    rand::thread_rng().fill_bytes(&mut data);
    let write_stream = Cursor::new(data.to_vec());

    let write = WriteBuilder::new()
        .data(Data::Stream(write_stream.clone()))
        .published(true)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record with block store data.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    assert!(read_reply.entry.records_write.is_some());
    let Some(read_stream) = read_reply.entry.data else {
        panic!("should have data");
    };

    let read_cid = cid::from_reader(read_stream.clone()).expect("should compute CID");
    let write_cid = cid::from_reader(write_stream.clone()).expect("should compute CID");

    assert_eq!(read_cid, write_cid);
}

// Should decrypt flat-space schema-contained records using a derived key.
#[tokio::test]
async fn decrypt_schema() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    let alice_key_ref = alice.verification_method().await.expect("should get kid");
    let Key::KeyId(alice_kid) = alice_key_ref else {
        panic!("should be KeyId");
    };

    let schema = String::from("https://some-schema.com");
    let data_format = String::from("some/format");

    // --------------------------------------------------
    // Alice derives and issues participants' keys.
    // The keys are used for decrypting data for selected messages with each
    // key 'locked' to it's derivation scheme and path.
    //
    // N.B.
    // - the root private key is the owner's private key
    // - derived private keys are encrypted (using recipient's public key) and
    //   distributed to each recipient (out of band)
    // --------------------------------------------------
    // schema encryption key
    let schema_root = DerivedPrivateJwk {
        root_key_id: alice_kid.clone(),
        derivation_scheme: DerivationScheme::Schemas,
        derivation_path: None,
        derived_private_key: PrivateKeyJwk {
            public_key: PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(
                    &alice.public_key().await.expect("should get public key").to_bytes(),
                ),
                ..PublicKeyJwk::default()
            },
            d: "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30".to_string(),
        },
    };

    let path = vec![DerivationScheme::Schemas.to_string(), schema.clone()];
    let schema_leaf = hd_key::derive_jwk(schema_root.clone(), &DerivationPath::Full(&path))
        .expect("should derive private key");
    let schema_public = schema_leaf.derived_private_key.public_key.clone();

    // data format encryption key
    let mut data_formats_root = schema_root.clone(); // same root as schema
    data_formats_root.derivation_scheme = DerivationScheme::DataFormats;
    let path = vec![DerivationScheme::DataFormats.to_string(), schema.clone(), data_format.clone()];
    let data_formats_leaf =
        hd_key::derive_jwk(data_formats_root.clone(), &DerivationPath::Full(&path))
            .expect("should derive private key");
    let data_formats_public = data_formats_leaf.derived_private_key.public_key.clone();

    // --------------------------------------------------
    // Alice writes a record with encrypted data.
    // --------------------------------------------------
    let options = EncryptOptions::new()
        .with_recipient(Recipient {
            key_id: alice_kid.clone(),
            public_key: schema_public,
            derivation_scheme: DerivationScheme::Schemas,
        })
        .with_recipient(Recipient {
            key_id: alice_kid.clone(),
            public_key: data_formats_public,
            derivation_scheme: DerivationScheme::DataFormats,
        });

    // generate data and encrypt
    let data = "hello world".as_bytes().to_vec();
    let encrypted = options.data(&data).encrypt().expect("should encrypt");
    let ciphertext = encrypted.ciphertext.clone();
    let encryption = encrypted.finalize().expect("should encrypt");

    // create Write record
    let write = WriteBuilder::new()
        .data(Data::from(ciphertext))
        .schema(schema)
        .data_format(&data_format)
        .encryption(encryption)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record with encrypted data and decrypts it.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let write = read_reply.entry.records_write.expect("should have write");

    let mut read_stream = read_reply.entry.data.expect("should have data");
    let mut encrypted = Vec::new();
    read_stream.read_to_end(&mut encrypted).expect("should read data");

    // decrypt using schema descendant key
    let plaintext = decrypt(&encrypted, &write, &schema_leaf, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);

    // decrypt using data format descendant key
    let plaintext =
        decrypt(&encrypted, &write, &data_formats_leaf, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);

    // decrypt using schema root key
    let plaintext = decrypt(&encrypted, &write, &schema_root, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);

    // decrypt using data format root key
    let plaintext =
        decrypt(&encrypted, &write, &data_formats_root, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);

    // --------------------------------------------------
    // Check decryption fails using key derived from invalid path.
    // --------------------------------------------------
    let invalid_path = vec![DerivationScheme::DataFormats.to_string(), data_format];
    let invalid_key =
        hd_key::derive_jwk(data_formats_root.clone(), &DerivationPath::Full(&invalid_path))
            .expect("should derive private key");

    let Err(e) = decrypt(&encrypted, &write, &invalid_key, alice).await else {
        panic!("should be error");
    };
    assert_eq!(e.to_string(), "ancestor and descendant key derivation segments do not match");
}

// Should decrypt flat-space schemaless records using a derived key.
#[tokio::test]
async fn decrypt_schemaless() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    // --------------------------------------------------
    // Alice derives participants' keys.
    // --------------------------------------------------
    let alice_key_ref = alice.verification_method().await.expect("should get kid");
    let Key::KeyId(alice_kid) = alice_key_ref else {
        panic!("should be KeyId");
    };
    let data_format = String::from("image/jpg");

    // encryption key
    let data_formats_root = DerivedPrivateJwk {
        root_key_id: alice_kid.clone(),
        derivation_scheme: DerivationScheme::DataFormats,
        derivation_path: None,
        derived_private_key: PrivateKeyJwk {
            public_key: PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(
                    &alice.public_key().await.expect("should get public key").to_bytes(),
                ),
                ..PublicKeyJwk::default()
            },
            d: "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30".to_string(),
        },
    };

    let path = vec![DerivationScheme::DataFormats.to_string(), data_format.clone()];
    let data_formats_leaf =
        hd_key::derive_jwk(data_formats_root.clone(), &DerivationPath::Full(&path))
            .expect("should derive private key");
    let data_formats_public = data_formats_leaf.derived_private_key.public_key.clone();

    // --------------------------------------------------
    // Alice writes a record with encrypted data.
    // --------------------------------------------------
    // generate data and encrypt
    let data = "hello world".as_bytes().to_vec();

    let encrypted = EncryptOptions::new()
        .data(&data)
        .with_recipient(Recipient {
            key_id: alice_kid.clone(),
            public_key: data_formats_public,
            derivation_scheme: DerivationScheme::DataFormats,
        })
        .encrypt()
        .expect("should encrypt");

    let ciphertext = encrypted.ciphertext.clone();
    let encryption = encrypted.finalize().expect("should encrypt");

    // create Write record
    let write = WriteBuilder::new()
        .data(Data::from(ciphertext))
        .data_format(&data_format)
        .encryption(encryption)
        .sign(alice)
        .build()
        .await
        .expect("should create write");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Alice reads the record with encrypted data and decrypts it.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let write = read_reply.entry.records_write.expect("should have write");

    let mut read_stream = read_reply.entry.data.expect("should have data");
    let mut encrypted = Vec::new();
    read_stream.read_to_end(&mut encrypted).expect("should read data");

    // decrypt using schema descendant key
    let plaintext =
        decrypt(&encrypted, &write, &data_formats_root, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);
}

// Should only be able to decrypt records using the correct derived private key
// within a protocol-context derivation scheme.
#[tokio::test]
async fn decrypt_context() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice's keys.
    // --------------------------------------------------
    let alice_key_ref = alice.verification_method().await.expect("should get kid");
    let Key::KeyId(alice_kid) = alice_key_ref else {
        panic!("should be KeyId");
    };
    let alice_private_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(
                &alice.public_key().await.expect("should get public key").to_bytes(),
            ),
            ..PublicKeyJwk::default()
        },
        d: "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30".to_string(),
    };

    // --------------------------------------------------
    // Bob's keys.
    // --------------------------------------------------
    let bob_key_ref = bob.verification_method().await.expect("should get kid");
    let Key::KeyId(bob_kid) = bob_key_ref else {
        panic!("should be KeyId");
    };
    let bob_private_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(
                &bob.public_key().await.expect("should get public key").to_bytes(),
            ),
            ..PublicKeyJwk::default()
        },
        d: "n8Rcm64tLob0nveDUuXzP-CnLmn3V11vRqk6E3FuKCo".to_string(),
    };

    // --------------------------------------------------
    // Alice configures the chat protocol with encryption.
    // --------------------------------------------------
    let chat = include_bytes!("../examples/protocols/chat.json");
    let definition: Definition = serde_json::from_slice(chat).expect("should deserialize");
    let definition = definition
        .with_encryption(&alice_kid, alice_private_jwk.clone())
        .expect("should add encryption");

    let configure_alice = ConfigureBuilder::new()
        .definition(definition)
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), configure_alice, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob configures the chat protocol with encryption.
    // --------------------------------------------------
    let definition: Definition = serde_json::from_slice(chat).expect("should deserialize");
    let definition = definition
        .with_encryption(&bob_kid, bob_private_jwk.clone())
        .expect("should add encryption");

    let configure_bob = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(bob)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&bob.did().await.expect("did"), configure_bob, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Bob queries for Alice's chat protocol definition.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://chat-protocol.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), query, &provider)
        .await
        .expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].authorization.author().unwrap(), alice.did().await.expect("did"));

    // --------------------------------------------------
    //  Bob writes an initiating chat thread to ALice's web node.
    // --------------------------------------------------
    // generate data and encrypt
    let data = "Hello Alice".as_bytes().to_vec();
    let mut options = EncryptOptions::new().data(&data);
    let mut encrypted = options.encrypt().expect("should encrypt");

    // create Write record
    let mut write = WriteBuilder::new()
        .data(Data::from(encrypted.ciphertext.clone()))
        .protocol(ProtocolBuilder {
            protocol: "http://chat-protocol.xyz",
            protocol_path: "thread",
            parent_context_id: None,
        })
        .schema("thread")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    // get the rule set for the protocol path
    let rule_set = definition.structure.get("thread").unwrap();
    let encryption = rule_set.encryption.as_ref().unwrap();

    // protocol path derived public key
    encrypted = encrypted.add_recipient(Recipient {
        key_id: encryption.root_key_id.clone(),
        public_key: encryption.public_key_jwk.clone(),
        derivation_scheme: DerivationScheme::ProtocolPath,
    });

    // protocol context derived public key
    let bob_root = DerivedPrivateJwk {
        root_key_id: bob_kid.clone(),
        derivation_scheme: DerivationScheme::ProtocolContext,
        derivation_path: None,
        derived_private_key: bob_private_jwk.clone(),
    };

    let context_id = write.context_id.clone().unwrap();
    let context_path = [DerivationScheme::ProtocolContext.to_string(), context_id.clone()];
    let context_jwk = hd_key::derive_jwk(bob_root.clone(), &DerivationPath::Full(&context_path))
        .expect("should derive key");

    encrypted = encrypted.add_recipient(Recipient {
        key_id: bob_kid.clone(),
        public_key: context_jwk.derived_private_key.public_key.clone(),
        derivation_scheme: DerivationScheme::ProtocolContext,
    });

    // generate data and encrypt
    let encryption = encrypted.finalize().expect("should encrypt");

    // finalize Write record
    write.encryption = Some(encryption);
    write.sign_as_author(None, None, bob).await.expect("should sign");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Bob also writes the message to his web node.
    // --------------------------------------------------
    let reply = credibil_dwn::handle(&bob.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Anyone with the protocol context derived private key should be able to
    // decrypt the message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let write = read_reply.entry.records_write.expect("should have write");

    let mut read_stream = read_reply.entry.data.expect("should have data");
    let mut encrypted = Vec::new();
    read_stream.read_to_end(&mut encrypted).expect("should read data");

    // decrypt using context-derived descendant key
    let plaintext = decrypt(&encrypted, &write, &context_jwk, alice).await.expect("should decrypt");
    assert_eq!(plaintext, data);

    // --------------------------------------------------
    // Alice sends Bob an encrypted message using the protocol
    // context public key derived above.
    // --------------------------------------------------
    // generate data and encrypt
    let data = "Hello Bob".as_bytes().to_vec();
    let mut options = EncryptOptions::new().data(&data);
    let mut encrypted = options.encrypt().expect("should encrypt");

    // create Write record
    let mut write = WriteBuilder::new()
        .data(Data::from(encrypted.ciphertext.clone()))
        .protocol(ProtocolBuilder {
            protocol: "http://chat-protocol.xyz",
            protocol_path: "thread/message",
            parent_context_id: Some(context_id.clone()),
        })
        .schema("message")
        .data_format("application/json")
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    // get the rule set for the protocol path
    let rule_set = definition.structure.get("thread").unwrap();
    let _encryption = rule_set.encryption.as_ref().unwrap();

    let context_id = write.context_id.clone().unwrap();
    let segment_1 = context_id.split("/").collect::<Vec<&str>>()[0];
    let context_path = [DerivationScheme::ProtocolContext.to_string(), segment_1.to_string()];
    let context_jwk = hd_key::derive_jwk(bob_root.clone(), &DerivationPath::Full(&context_path))
        .expect("should derive key");

    encrypted = encrypted.add_recipient(Recipient {
        key_id: bob_kid.clone(),
        public_key: context_jwk.derived_private_key.public_key.clone(),
        derivation_scheme: DerivationScheme::ProtocolContext,
    });

    // generate data and encrypt
    let encryption = encrypted.finalize().expect("should encrypt");

    // finalize Write record
    write.encryption = Some(encryption);
    write.sign_as_author(None, None, bob).await.expect("should sign");

    let reply = credibil_dwn::handle(&bob.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    // Bob reads Alice's message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(bob)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&bob.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let write = read_reply.entry.records_write.expect("should have write");

    let mut read_stream = read_reply.entry.data.expect("should have data");
    let mut encrypted = Vec::new();
    read_stream.read_to_end(&mut encrypted).expect("should read data");

    // decrypt using context-derived descendant key
    let plaintext = decrypt(&encrypted, &write, &context_jwk, bob).await.expect("should decrypt");
    assert_eq!(plaintext, data);
}

// Should only be able to decrypt records using the correct derived private key
// within a protocol derivation scheme.
#[tokio::test]
async fn decrypt_protocol() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;
    let bob = bob().await;

    // --------------------------------------------------
    // Alice's keys.
    // --------------------------------------------------
    let alice_key_ref = alice.verification_method().await.expect("should get kid");
    let Key::KeyId(alice_kid) = alice_key_ref else {
        panic!("should be KeyId");
    };

    let alice_private_jwk = PrivateKeyJwk {
        public_key: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(
                &alice.public_key().await.expect("get public key").to_bytes(),
            ),
            ..PublicKeyJwk::default()
        },
        d: "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30".to_string(),
    };

    // --------------------------------------------------
    // Alice configures the email protocol with encryption.
    // --------------------------------------------------
    let email = include_bytes!("../examples/protocols/email.json");
    let definition: Definition = serde_json::from_slice(email).expect("should deserialize");
    let definition = definition
        .with_encryption(&alice_kid, alice_private_jwk.clone())
        .expect("should add encryption");

    let email = ConfigureBuilder::new()
        .definition(definition.clone())
        .sign(alice)
        .build()
        .await
        .expect("should build");
    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), email, &provider)
        .await
        .expect("should configure protocol");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Bob queries for Alice's email protocol definition.
    // --------------------------------------------------
    let query = QueryBuilder::new()
        .filter("http://email-protocol.xyz")
        .sign(bob)
        .build()
        .await
        .expect("should build");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), query, &provider)
        .await
        .expect("should match");
    assert_eq!(reply.status, StatusCode::OK);

    let query_reply: QueryReply = reply.body;
    let entries = query_reply.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].authorization.author().unwrap(), alice.did().await.expect("did"));

    // --------------------------------------------------
    //  Bob writes an encrypted email to ALICE.
    // --------------------------------------------------
    // generate data and encrypt
    let data = "Hello Alice".as_bytes().to_vec();
    let mut options = EncryptOptions::new().data(&data);
    let mut encrypted = options.encrypt().expect("should encrypt");
    let ciphertext = encrypted.ciphertext.clone();

    // get the rule set for the protocol path
    let rule_set = definition.structure.get("email").unwrap();
    let encryption = rule_set.encryption.as_ref().unwrap();

    // protocol path derived public key
    encrypted = encrypted.add_recipient(Recipient {
        key_id: alice_kid.clone(),
        public_key: encryption.public_key_jwk.clone(),
        derivation_scheme: DerivationScheme::ProtocolPath,
    });

    // generate data and encrypt
    let encryption = encrypted.finalize().expect("should encrypt");

    // create Write record
    let write = WriteBuilder::new()
        .data(Data::from(ciphertext))
        .protocol(ProtocolBuilder {
            protocol: "http://email-protocol.xyz",
            protocol_path: "email",
            parent_context_id: None,
        })
        .schema("email")
        .data_format("text/plain")
        .encryption(encryption)
        .sign(bob)
        .build()
        .await
        .expect("should create write");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), write.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // --------------------------------------------------
    //  Alice read Bob's message.
    // --------------------------------------------------
    let read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(alice)
        .build()
        .await
        .expect("should create read");

    let reply = credibil_dwn::handle(&alice.did().await.expect("did"), read.clone(), &provider)
        .await
        .expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let read_reply: ReadReply = reply.body;
    let write = read_reply.entry.records_write.expect("should have write");

    let mut read_stream = read_reply.entry.data.expect("should have data");
    let mut encrypted = Vec::new();
    read_stream.read_to_end(&mut encrypted).expect("should read data");

    // decrypt using her private key
    let alice_jwk = DerivedPrivateJwk {
        root_key_id: alice_kid.clone(),
        derivation_scheme: DerivationScheme::ProtocolPath,
        derivation_path: None,
        derived_private_key: alice_private_jwk.clone(),
    };

    let plaintext = decrypt(&encrypted, &write, &alice_jwk, bob).await.expect("should decrypt");
    assert_eq!(plaintext, data);
}

// Should return Unauthorized (401) for invalid signatures.
#[tokio::test]
async fn invalid_signature() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    let mut read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id("somerecordid".to_string()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    read.authorization.as_mut().unwrap().signature.signatures[0].signature =
        "badsignature".to_string();

    let Err(Error::Unauthorized(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be Unauthorized");
    };
    assert!(e.starts_with("failed to authenticate: "));
}

// Should return BadRequest (400) for unparsable messages.
#[tokio::test]
async fn invalid_message() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice = alice().await;

    let mut read = ReadBuilder::new()
        .filter(RecordsFilter::new().record_id("somerecordid".to_string()))
        .sign(alice)
        .build()
        .await
        .expect("should create query");

    read.descriptor.filter = RecordsFilter::default();

    let Err(Error::BadRequest(e)) =
        credibil_dwn::handle(&alice.did().await.expect("did"), read, &provider).await
    else {
        panic!("should be BadRequest");
    };
    assert!(e.contains("validation failed:"));
}
