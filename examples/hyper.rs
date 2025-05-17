//! A simple Hyper HTTP server that handles DWN messages.

use anyhow::Result;
use credibil_dwn::interfaces::{messages, protocols, records};
use credibil_dwn::{self, IntoHttp};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use test_utils::{Identity, ProviderImpl};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Alice's DWN listening on http://0.0.0.0:8080");

    let svc = Svc {
        owner: Identity::new("alice").await.did().to_string(),
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
    async fn handle(&self, req: hyper::Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>> {
        let path = req.uri().path().to_string();
        let body = req.into_body().collect().await.expect("should have body");

        match path.as_str() {
            "/messages/query" => {
                let request = serde_json::from_slice::<messages::Query>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/messages/read" => {
                let request = serde_json::from_slice::<messages::Read>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/messages/subscribe" => {
                let request = serde_json::from_slice::<messages::Subscribe>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/protocols/configure" => {
                let request = serde_json::from_slice::<protocols::Configure>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/protocols/query" => {
                let request = serde_json::from_slice::<protocols::Query>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/records/delete" => {
                let request = serde_json::from_slice::<records::Delete>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/records/query" => {
                let request = serde_json::from_slice::<records::Query>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/records/read" => {
                let request = serde_json::from_slice::<records::Read>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/records/subscribe" => {
                let request = serde_json::from_slice::<records::Subscribe>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "/records/write" => {
                let request = serde_json::from_slice::<records::Write>(&body.to_bytes())?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            _ => Err(anyhow::anyhow!("path {path} is not supported")),
        }
    }
}
