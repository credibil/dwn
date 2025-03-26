mod provider;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use credibil_dwn::client::messages::Query;
use credibil_dwn::endpoint::{self, Message, Reply};
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// use
use crate::provider::ProviderImpl;

#[tokio::main]
async fn main() {
    let provider = ProviderImpl::new().await.expect("should create Provider");

    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let router = Router::new()
        .route("/", post(handle::<Query>))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(provider);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

// Credential Offer endpoint
// #[axum::debug_handler]
async fn handle<T>(State(provider): State<ProviderImpl>, Json(req): Json<T>) -> impl IntoResponse
where
    T: Message,
    <T as Message>::Reply: Serialize,
{
    let reply: Reply<<T as Message>::Reply> =
        endpoint::handle("did:web:credibil.io", req, &provider).await.expect("should handle");

    (StatusCode::OK, Json(json!(reply.body))).into_response()
}
