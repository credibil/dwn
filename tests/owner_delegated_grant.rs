//! Owner Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! an app to perform an action on their behalf. In this case, Alice
//! grants App X the ability to post as her for the `chat` protocol.

use dwn_test::keystore::{ALICE_DID, APP_DID, BOB_DID};
use dwn_test::store::ProviderImpl;
use rand::RngCore;
use vercre_dwn::permissions::{GrantBuilder, ScopeType};
use vercre_dwn::provider::KeyStore;
use vercre_dwn::records::{DelegatedGrant, WriteBuilder, WriteData};
use vercre_dwn::{Interface, Method};

#[tokio::test]
async fn configure() {
    let provider = ProviderImpl::new().await.expect("should create provider");
    let alice_keyring = provider.keyring(ALICE_DID).expect("should get Alice's keyring");
    let bob_keyring = provider.keyring(BOB_DID).expect("should get Bobs's keyring");
    let appx_keyring = provider.keyring(APP_DID).expect("should get AppX's keyring");

    // --------------------------------------------------
    // Alice grants App X to write as her for the `chat` protocol
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(APP_DID)
        .request_id("grant_id_1")
        .description("allow App X to write as me in chat protocol")
        .delegated(true)
        .scope(
            Interface::Records,
            Method::Write,
            ScopeType::Records {
                protocol: "chat".to_string(),
                option: None,
            },
        );

    let grant_to_appx = builder.build(&alice_keyring).await.expect("should create grant");

    // --------------------------------------------------
    // Bob creates a RecordsWrite message
    // --------------------------------------------------
    let mut data = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut data);
    let write_data = WriteData::Bytes { data: data.to_vec() };

    let mut write = WriteBuilder::new()
        .data_format("application/octet-stream")
        .data(write_data)
        .build(&bob_keyring)
        .await
        .expect("should create write");

    // --------------------------------------------------
    // App X signs over Bob's RecordsWrite as owner but does
    // not include the delegated grant (removed below)
    // --------------------------------------------------
    // TODO: look at merging the `DelegatedGrant` into `Write`
    let delegated_grant = DelegatedGrant {
        authorization: Box::new(grant_to_appx.authorization),
        descriptor: grant_to_appx.descriptor,
        record_id: grant_to_appx.record_id,
        context_id: grant_to_appx.context_id,
        encoded_data: grant_to_appx.encoded_data.unwrap_or_default(),
    };
    write.sign_as_delegate(delegated_grant, &appx_keyring).await.expect("should sign");

    // intentionally remove `owner_delegated_grant` to cause exception
    write.authorization.owner_delegated_grant = None;

    //const parsePromise = RecordsWrite.parse(recordsWrite.message);
    // await expect(parsePromise).to.be.rejectedWith(DwnErrorCode.RecordsOwnerDelegatedGrantAndIdExistenceMismatch);
}
