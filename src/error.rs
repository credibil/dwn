//! # `DWN` Errors

use base64ct::Error as Base64Error;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

/// `DWN` errors.
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
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerdeError;

        let Ok(error) = serde_json::from_str::<DwnError>(&self.to_string()) else {
            return Err(SerdeError::custom("issue deserializing Err"));
        };
        error.serialize(serializer)
    }
}

impl Error {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::InternalServerError(_) => 500,
            Self::Unimplemented(_) => 501,
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.code() == other.code()
    }
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Self::InternalServerError(format!("anyhow: {error}"))
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: Base64Error) -> Self {
        Self::InternalServerError(format!("base64ct: {error}"))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::InternalServerError(format!("serde_json: {error}"))
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(error: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::InternalServerError(format!("ciborium: {error}"))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(error: http::uri::InvalidUri) -> Self {
        Self::InternalServerError(format!("http: {error}"))
    }
}

impl From<jsonschema::error::ValidationError<'_>> for Error {
    fn from(error: jsonschema::error::ValidationError<'_>) -> Self {
        Self::InternalServerError(format!("jsonschema: {error}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::InternalServerError(format!("std::io: {error}"))
    }
}

/// Construct an `Error::BadRequest` error from a string or existing error
/// value.
#[macro_export]
macro_rules! unexpected {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::BadRequest(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::BadRequest($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::Error::BadRequest(format!($err))
    };
}

/// Construct an `Error::Forbidden` error from a string or existing error
/// value.
#[macro_export]
macro_rules! forbidden {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Forbidden(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::Forbidden($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::Error::Forbidden(format!($err))
    };
}

/// Construct an `Error::Forbidden` error from a string or existing error
/// value.
#[macro_export]
macro_rules! unauthorized {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Unauthorized(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::Unauthorized($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::Error::Unauthorized(format!($err))
    };
}

// Error response for serializing internal errors to JSON.
#[derive(Deserialize, Serialize)]
struct DwnError {
    /// Error code.
    code: u16,

    /// Error description.
    detail: String,
}

impl Error {
    /// Transfrom error to `OpenID` compatible json format.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::from_str(&self.to_string()).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use serde_json::{Value, json};

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn err_json() {
        let err = Error::BadRequest("bad request".into());
        let ser: Value = serde_json::from_str(&err.to_string()).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad request"}));
    }

    // Test that the error details are returned as an http query string.
    #[test]
    fn macro_literal() {
        let err = unexpected!("bad request");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad request"}));
    }

    #[test]
    fn macro_expr() {
        let expr = anyhow!("bad request");
        let err = unexpected!("{expr}");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad request"}));
    }

    #[test]
    fn macro_tt() {
        let err = unexpected!("bad request: {}", "a token");
        let ser = serde_json::to_value(&err).unwrap();
        assert_eq!(ser, json!({"code": 400, "detail": "bad request: a token"}));
    }
}
