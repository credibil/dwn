use test_utils::store::ProviderImpl;
use vercre_dwn::protocols::{self};
use vercre_dwn::service::Message;

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create provider");

    // let msg = Message::MessagesQuery(messages::Query::default());

    let mut query = protocols::Query::default();
    query.descriptor.filter = Some(protocols::query::Filter {
        protocol: "https://decentralized-social-example.org/protocol/".to_string(),
    });
    let msg = Message::ProtocolsQuery(query);

    let reply =
        vercre_dwn::handle_message("tenant", msg, provider).await.expect("should send message");
    println!("{:?}", reply);
}
