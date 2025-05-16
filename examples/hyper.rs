//! A simple Hyper HTTP server that handles DWN messages.

mod provider;

use std::convert::Infallible;

use anyhow::Result;
use credibil_dwn::interfaces::records;
use credibil_dwn::{self, IntoHttp};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::provider::ProviderImpl;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Listening on http://0.0.0.0:8080");

    let svc = Svc {
        provider: ProviderImpl::new().await?,
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc = svc.clone();

        tokio::task::spawn(async move {
            let http1 = http1::Builder::new();
            if let Err(e) = http1.serve_connection(io, service_fn(|req| svc.handle(req))).await {
                eprintln!("Error serving connection: {e}");
            }
        });
    }
}

#[derive(Clone)]
struct Svc {
    provider: ProviderImpl,
}

impl Svc {
    // Handle all DWN messages.
    async fn handle(
        &self, req: hyper::Request<Incoming>,
    ) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_string();
        let body = req.into_body().collect().await.unwrap();
        let did = path.trim_start_matches('/').to_string();

        let request = match path.as_str() {
            "/:did/read/records/:id" => {
                serde_json::from_slice::<records::Read>(&body.to_bytes()).unwrap()
            }
            _ => todo!(), //into_response("oh no! not found".into()),
        };

        Ok(credibil_dwn::handle(&did, request, &self.provider).await.into_http())
    }
}
