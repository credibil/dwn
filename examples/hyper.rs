//! A simple Hyper HTTP server that handles DWN messages.

mod provider;

use std::convert::Infallible;

use anyhow::Result;
use credibil_dwn::endpoint::{self, IntoHttp, Message};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::provider::ProviderImpl;

#[tokio::main]
async fn main() -> Result<()> {
    let provider = ProviderImpl::new().await?;
    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    println!("Listening on http://0.0.0.0:8080");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let provider = provider.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(|req| handle(req, &provider)))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

// Handle all DWN messages.
async fn handle(
    req: Request<Incoming>, provider: &ProviderImpl,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let did = req.uri().path().trim_start_matches('/').to_string();

    let body = req.into_body();
    let collected = body.collect().await.unwrap();
    let req: Message = serde_json::from_slice(&collected.to_bytes()).unwrap();

    Ok(endpoint::handle(&did, req, provider).await.into_http())
}
