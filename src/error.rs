//! # `DWN` Errors

use serde::{Deserialize, Serialize, Serializer, ser};
use serde_json::Value;
use thiserror::Error;

/// The Error type represents all errors that may be returned by a `DWN`.
///
/// The error type is a `serde` serializable type that can be used to return
/// JSON error responses to HTTP clients.
#[derive(Error, Debug, Deserialize)]
pub enum Error {
    /// The server cannot or will not process the request due to something that
    /// is perceived to be a client error.
    #[error(r#"{{"code": 400, "detail": "{0}"}}"#)]
    BadRequest(String),

    /// Semantically, this response means 'unauthenticated'.
    #[error(r#"{{"code": 401, "detail": "{0}"}}"#)]
    Unauthorized(String),

    /// The client does not have access rights to the content, i.e. is unauthorized.
    #[error(r#"{{"code": 403, "detail": "{0}"}}"#)]
    Forbidden(String),

    /// A required resource was not found.
    #[error(r#"{{"code": 404, "detail": "{0}"}}"#)]
    NotFound(String),

    /// A database write conflict occurred.
    #[error(r#"{{"code": 409, "detail": "{0}"}}"#)]
    Conflict(String),

    /// The server has encountered a situation it does not know how to handle.
    /// Used when the web node encounters an unexpected condition in a dependant
    /// library.
    #[error(r#"{{"code": 500, "detail": "{0}"}}"#)]
    InternalServerError(String),

    /// The request method is not supported by the server and cannot be handled.
    #[error(r#"{{"code": 501, "detail": "{0}"}}"#)]
    Unimplemented(String),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value: Value = serde_json::from_str(&self.to_string())
            .map_err(|e| ser::Error::custom(format!("issue serializing error: {e}")))?;
        value.serialize(serializer)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast_ref::<Self>() {
            Some(Self::BadRequest(e)) => Self::BadRequest(format!("{err}: {e}")),
            Some(Self::Unauthorized(e)) => Self::Unauthorized(format!("{err}: {e}")),
            Some(Self::Forbidden(e)) => Self::Forbidden(format!("{err}: {e}")),
            Some(Self::NotFound(e)) => Self::NotFound(format!("{err}: {e}")),
            Some(Self::Conflict(e)) => Self::Conflict(format!("{err}: {e}")),
            Some(Self::InternalServerError(e)) => Self::InternalServerError(format!("{err}: {e}")),
            Some(Self::Unimplemented(e)) => Self::Unimplemented(format!("{err}: {e}")),
            None => {
                let source = err.source().map_or_else(String::new, ToString::to_string);
                Self::InternalServerError(format!("{err}: {source}"))
            }
        }
    }
}

/// Construct an `Error::BadRequest` error from a string or existing error
/// value.
macro_rules! bad_request {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::BadRequest(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::BadRequest($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::error::Error::BadRequest(format!($err))
    };
}
pub(crate) use bad_request;

/// Construct an `Error::Forbidden` error from a string or existing error
/// value.
macro_rules! forbidden {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::Forbidden(format!($fmt, $($arg)*))
    };
     ($err:expr $(,)?) => {
        $crate::error::Error::Forbidden(format!($err))
    };
}
pub(crate) use forbidden;

/// Construct an `Error::Unauthorized` error from a string or existing error
/// value.
macro_rules! unauthorized {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::Unauthorized(format!($fmt, $($arg)*))
    };
     ($err:expr $(,)?) => {
        $crate::error::Error::Unauthorized(format!($err))
    };
}
pub(crate) use unauthorized;

#[cfg(test)]
mod test {

    use anyhow::{Context, Result, anyhow};
    use serde_json::{Value, json};

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn dwn_context() {
        let err = dwn_error().unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"{"code": 400, "detail": "request context: some invalid request"}"#
        );
    }
    fn dwn_error() -> Result<(), Error> {
        Err(Error::BadRequest("some invalid request".to_string())).context("request context")?
    }

    #[test]
    fn anyhow_context() {
        let err = anyhow_error().unwrap_err();
        assert_eq!(err.to_string(), r#"{"code": 500, "detail": "error context: one-off error"}"#);
    }
    fn anyhow_error() -> Result<(), Error> {
        Err(anyhow!("one-off error")).context("error context")?
    }

    // Test that error details are retuned as json.
    #[test]
    fn json() {
        let err = Error::BadRequest("bad request request".into());
        let ser: Value = serde_json::from_str(&err.to_string()).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad request request"}));
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn macro_literal() {
        let err = bad_request!("bad request");
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value, json!({"code": 400, "detail": "bad request"}));
    }

    #[test]
    fn macro_expr() {
        let expr = anyhow!("bad_request request");
        let err = bad_request!("{expr}");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad_request request"}));
    }

    #[test]
    fn macro_tt() {
        let err = bad_request!("bad_request request: {}", "a token");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad_request request: a token"}));
    }
}
