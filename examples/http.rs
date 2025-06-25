//! # HTTP Server Example
//!
//! This example demonstrates how to use the Verifiable Credential Issuer (VCI)

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use credibil_dwn::api::Client;
use credibil_dwn::http::IntoHttp;
use credibil_dwn::interfaces::{messages, protocols, records};
use test_utils::{Identity, Provider};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let owner = Identity::new("alice").await.did().to_string();
    let client = Client::new(owner, Provider::new().await);

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");
    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/messages/query", post(messages_query))
        .route("/messages/read", post(messages_read))
        .route("/messages/subscribe", post(messages_subscribe))
        .route("/protocols/configure", post(protocols_configure))
        .route("/protocols/query", get(protocols_query))
        .route("/records/delete", get(records_delete))
        .route("/records/query", post(records_query))
        .route("/records/read", post(records_read))
        .route("/records/subscribe", post(records_subscribe))
        .route("/records/write", post(records_write))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(client);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    Ok(axum::serve(listener, router).await?)
}

#[axum::debug_handler]
async fn messages_query(
    State(client): State<Client<Provider>>, Json(request): Json<messages::Query>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn messages_read(
    State(client): State<Client<Provider>>, Json(request): Json<messages::Read>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn messages_subscribe(
    State(client): State<Client<Provider>>, Json(request): Json<messages::Subscribe>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn protocols_configure(
    State(client): State<Client<Provider>>, Json(request): Json<protocols::Configure>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn protocols_query(
    State(client): State<Client<Provider>>, Json(request): Json<protocols::Query>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn records_delete(
    State(client): State<Client<Provider>>, Json(request): Json<records::Delete>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn records_query(
    State(client): State<Client<Provider>>, Json(request): Json<records::Query>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn records_read(
    State(client): State<Client<Provider>>, Json(request): Json<records::Read>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn records_subscribe(
    State(client): State<Client<Provider>>, Json(request): Json<records::Subscribe>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}

#[axum::debug_handler]
async fn records_write(
    State(client): State<Client<Provider>>, Json(request): Json<records::Write>,
) -> impl IntoResponse {
    client.request(request).execute().await.into_http()
}
