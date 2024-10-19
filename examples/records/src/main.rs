use vercre_dwn::protocols::{self};
use vercre_dwn::service::Message;

use test_utils::store::ProviderImpl;

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // let msg = Message::MessagesQuery(messages::Query::default());

    let mut query = protocols::Query::default();
    query.descriptor.filter = Some(protocols::query::Filter {
        protocol: "https://decentralized-social-example.org/protocol/".to_string(),
    });
    let msg = Message::ProtocolsQuery(query);

    let _ = vercre_dwn::send_message(msg, provider).await.expect("should send message");
}
