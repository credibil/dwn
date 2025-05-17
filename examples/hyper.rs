//! A simple Hyper HTTP server that handles DWN messages.

#[path = "../examples/kms/mod.rs"]
mod kms;
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
use kms::Keyring;
use tokio::net::TcpListener;

use crate::provider::ProviderImpl;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Listening on http://0.0.0.0:8080");

    let keyring = Keyring::new("alice").await.expect("should create keyring");
    let owner = keyring.did().await.expect("should get did");

    let svc = Svc {
        owner,
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
    owner: String,
    provider: ProviderImpl,
}

impl Svc {
    // Handle DWN messages.
    async fn handle(
        &self, req: hyper::Request<Incoming>,
    ) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_string();
        let body = req.into_body().collect().await.unwrap();

        let request = match path.as_str() {
            "/read/records/:id" => {
                serde_json::from_slice::<records::Read>(&body.to_bytes()).unwrap()
            }
            _ => todo!(),
        };

        Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
    }
}

// async fn into_records_read (req: hyper::Request<Incoming>) -> Result<records::Read, Infallible> {
//     // const record = await RecordsRead.create({
//     //   filter: { recordId: req.params.id },
//     // });

//     let read= serde_json::from_slice::<records::Read>(&body.to_bytes()).unwrap();

//   }
