//! Owner Delegated Grant
//!
//! This test demonstrates how a web node owner can delegate permission to
//! an app to perform an action on their behalf. In this case, Alice
//! grants App X the ability to post as her for the `chat` protocol.

use std::sync::LazyLock;

use dwn_node::Method;
use dwn_node::client::grants::{GrantBuilder, Scope};
use dwn_node::client::records::{Data, DelegatedGrant, WriteBuilder};
use rand::RngCore;
use test_node::keystore::{self, Keyring};

static ALICE: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static BOB: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());
static APP: LazyLock<Keyring> = LazyLock::new(|| keystore::new_keyring());

#[tokio::test]
async fn configure() {
    // --------------------------------------------------
    // Alice grants App X to write as her for the `chat` protocol
    // --------------------------------------------------
    let builder = GrantBuilder::new()
        .granted_to(&APP.did)
        .request_id("grant_id_1")
        .description("allow App X to write as me in chat protocol")
        .delegated(true)
        .scope(Scope::Records {
            method: Method::Write,
            protocol: "chat".to_string(),
            limited_to: None,
        });
    let grant_to_appx = builder.sign(&*ALICE).build().await.expect("should create grant");

    // --------------------------------------------------
    // Bob creates a RecordsWrite message
    // --------------------------------------------------
    let mut data = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut data);
    let write_data = Data::from(data.to_vec());

    let mut write = WriteBuilder::new()
        .data_format("application/octet-stream")
        .data(write_data)
        .sign(&*BOB)
        .build()
        .await
        .expect("should create write");

    // --------------------------------------------------
    // App X signs over Bob's RecordsWrite as owner but does
    // not include the delegated grant (removed below)
    // --------------------------------------------------
    // LATER: investigate merging `DelegatedGrant` into `Write`
    let delegated_grant = DelegatedGrant {
        authorization: Box::new(grant_to_appx.authorization),
        descriptor: grant_to_appx.descriptor,
        record_id: grant_to_appx.record_id,
        context_id: grant_to_appx.context_id,
        encoded_data: grant_to_appx.encoded_data.unwrap_or_default(),
    };
    write.sign_as_delegate(delegated_grant, &*APP).await.expect("should sign");

    // intentionally remove `owner_delegated_grant` to cause exception
    write.authorization.owner_delegated_grant = None;

    //const parsePromise = RecordsWrite.parse(recordsWrite.message);
    // await expect(parsePromise).to.be.rejectedWith(DwnErrorCode.RecordsOwnerDelegatedGrantAndIdExistenceMismatch);
}
