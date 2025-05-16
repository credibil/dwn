//! A simple Axum HTTP server that handles DWN messages.

mod provider;

// use axum::extract::{Path, State};
// use axum::response::IntoResponse;
// use axum::routing::post;
// use axum::{Json, Router};
// use credibil_dwn::{self, IntoHttp, Message};
// use tokio::net::TcpListener;

// use crate::provider::ProviderImpl;

#[tokio::main]
async fn main() {
    // let provider = ProviderImpl::new().await.expect("should create");
    // let router = Router::new().route("/{did}", post(handle)).with_state(provider);
    // let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");

    println!("Listening on http://0.0.0.0:8080");

    // axum::serve(listener, router).await.expect("server should run");
}

// // Handle all DWN messages.
// #[axum::debug_handler]
// async fn handle(
//     State(provider): State<ProviderImpl>, Path(did): Path<String>, Json(req): Json<Message>,
// ) -> impl IntoResponse {
//     credibil_dwn::handle(&did, req, &provider).await.into_http()
// }
