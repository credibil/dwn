//! A simple Hyper HTTP server that handles DWN messages.

use anyhow::{Result, anyhow};
use credibil_dwn::interfaces::{Descriptor, messages, protocols, records};
use credibil_dwn::{self, IntoHttp};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use test_utils::{Identity, Provider};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Alice's DWN listening on http://0.0.0.0:8080");

    let svc = Svc {
        owner: Identity::new("alice").await.did().to_string(),
        provider: Provider::new().await?,
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
    provider: Provider,
}

impl Svc {
    // Handle DWN messages.
    async fn handle(&self, req: hyper::Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>> {
        let path = req.uri().path().to_string();

        match path.as_str() {
            "/" => self.process_message(req).await,
            "/health" => {
                let body = serde_json::to_vec(&json!({
                    "status": "ok",
                    "version": "0.1.0",
                }))?;
                Ok(hyper::Response::new(Full::from(body)))
            }
            _ => Err(anyhow::anyhow!("path {path} is not supported")),
        }
    }

    async fn process_message(
        &self, req: hyper::Request<Incoming>,
    ) -> Result<hyper::Response<Full<Bytes>>> {
        // process body into json-rpc
        let body = req.into_body().collect().await?.to_bytes();
        let rpc = serde_json::from_slice::<JsonRpc>(&body)?;

        // partially parse the message to determine the interface and method
        let Some(value) = rpc.params.message.get("descriptor") else {
            return Err(anyhow!("message has noo descriptor "));
        };
        let desc = serde_json::from_value::<Descriptor>(value.clone())?;

        match format!("{}{}", desc.interface, desc.method).as_str() {
            "MessagesQuery" => {
                let request = serde_json::from_value::<messages::Query>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "MessagesRead" => {
                let request = serde_json::from_value::<messages::Read>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "MessagesSubscribe" => {
                let request = serde_json::from_value::<messages::Subscribe>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "ProtocolsConfigure" => {
                let request = serde_json::from_value::<protocols::Configure>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "ProtocolsQuery" => {
                let request = serde_json::from_value::<protocols::Query>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "RecordsDelete" => {
                let request = serde_json::from_value::<records::Delete>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "RecordsQuery" => {
                let request = serde_json::from_value::<records::Query>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "RecordsRead" => {
                let request = serde_json::from_value::<records::Read>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "RecordsSubscribe" => {
                let request = serde_json::from_value::<records::Subscribe>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            "RecordsWrite" => {
                let request = serde_json::from_value::<records::Write>(rpc.params.message)?;
                Ok(credibil_dwn::handle(&self.owner, request, &self.provider).await.into_http())
            }
            _ => Err(anyhow!("{}{} is invalid", desc.interface, desc.method)),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRpc {
    /// A string with the name of the method to be invoked.
    /// Should be `dwn.processMessage`
    method: String,

    /// An object or array of values to be passed as parameters to the defined method.
    params: Params,

    /// Used to match the response with the request that it is replying to.
    id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    /// The DID that the message is intended for
    target: String,

    /// The DWN Message
    message: serde_json::Value,

    /// Data associated with the message (e.g. `RecordsWrite` encoded data)
    #[serde(skip_serializing_if = "Option::is_none")]
    encoded_data: Option<String>,
}
