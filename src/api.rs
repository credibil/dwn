//! # API
//!
//! The api module provides the entry point to the public API. Requests are
//! routed to the appropriate handler for processing, returning a response that
//! can be serialized to a JSON object or directly to HTTP.

use std::fmt::Debug;
use std::ops::Deref;

use bytes::Bytes;
use http::{Response, StatusCode, header};
use serde::Serialize;

pub use crate::error::Error;
use crate::error::unauthorized;
use crate::provider::Provider;
use crate::schema;

/// DWN handler `Result` type.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

/// A request to process.
#[derive(Clone, Debug)]
pub struct Request<B, H = NoHeaders>
where
    B: Body,
    H: Headers,
{
    /// The request to process.
    pub body: B,

    /// Headers associated with this request.
    pub headers: H,
}

impl<B: Body, H: Headers> Request<B, H> {
    /// Perform initial validation of the request.
    ///
    /// Validation undertaken here is common to all messages, with message-
    /// specific validation performed by the message's handler.
    ///
    /// # Errors
    ///
    /// Will fail if the request is invalid or if authentication fails.
    pub async fn validate(&self, _owner: &str, provider: &impl Provider) -> Result<()> {
        // if !tenant.active(owner)? {
        //     return Err(Error::Unauthorized("tenant not active"));
        // }

        #[cfg(debug_assertions)]
        schema::validate(&self.body)?;

        // authenticate the requestor
        if let Some(authzn) = self.body.authorization() {
            if let Err(e) = authzn.verify(provider).await {
                return Err(unauthorized!("failed to authenticate: {e}"));
            }
        }

        Ok(())
    }
}

impl<B: Body> From<B> for Request<B> {
    fn from(body: B) -> Self {
        Self {
            body,
            headers: NoHeaders,
        }
    }
}

/// Top-level response data structure common to all handler.
#[derive(Clone, Debug)]
pub struct Reply<T, H = NoHeaders>
where
    H: Headers,
{
    /// Response HTTP status code.
    pub status: StatusCode,

    /// Response HTTP headers, if any.
    pub headers: Option<H>,

    /// The endpoint-specific response.
    pub body: T,
}

impl<T> From<T> for Reply<T> {
    fn from(body: T) -> Self {
        Self {
            status: StatusCode::OK,
            headers: None,
            body,
        }
    }
}

impl<T> Deref for Reply<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

/// Request handler.
///
/// The primary role of this trait is to provide a common interface for
/// requests so they can be handled by [`handle`] method.
pub trait Handler<U, P> {
    /// The error type returned by the handler.
    type Error;

    /// Routes the message to the concrete handler used to process the message.
    fn handle(
        self, tenant: &str, provider: &P,
    ) -> impl Future<Output = Result<impl Into<Reply<U>>, Self::Error>> + Send;
}

/// Trait for converting a `Result` into an HTTP response.
pub trait IntoHttp {
    /// The body type of the HTTP response.
    type Body: http_body::Body<Data = Bytes> + Send + 'static;

    /// Convert into an HTTP response.
    fn into_http(self) -> http::Response<Self::Body>;
}

impl<U: Serialize> IntoHttp for Result<Reply<U>> {
    type Body = http_body_util::Full<Bytes>;

    /// Create a new reply with the given status code and body.
    fn into_http(self) -> Response<Self::Body> {
        let result = match self {
            Ok(r) => {
                let body = serde_json::to_vec(&r.body).unwrap_or_default();
                Response::builder()
                    .status(r.status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Self::Body::from(body))
            }
            Err(e) => {
                let body = serde_json::to_vec(&e).unwrap_or_default();
                Response::builder()
                    .status(e.status())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Self::Body::from(body))
            }
        };
        result.unwrap_or_default()
    }
}

/// 'Seal' `Header` and `Body` traits such that they can conly be implemented
/// by this module. This is to prevent users from implementing their own `Body`
/// and `Headers` types, which would break the API.
pub mod seal {
    use std::fmt::Debug;

    use serde::Serialize;

    use crate::authorization::Authorization;
    use crate::interfaces::Descriptor;

    /// The `Body` trait is used to restrict the types able to implement
    /// request body. It is implemented by all `xxxRequest` types.
    pub trait Body: Clone + Debug + Serialize + Send + Sync {
        /// The request's 'core' descriptor.
        fn descriptor(&self) -> &Descriptor;

        /// the Request's authorization, if any.
        fn authorization(&self) -> Option<&Authorization>;
    }

    /// The `Headers` trait is used to restrict the types able to implement
    /// request headers.
    pub trait Headers: Clone + Debug + Send + Sync {}
}
pub use seal::{Body, Headers};

/// Implement empty headers for use by handlers that do not require headers.
#[derive(Clone, Debug)]
pub struct NoHeaders;
impl Headers for NoHeaders {}
