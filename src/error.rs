//! # `DWN` Errors

use base64ct::Error as Base64Error;
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

/// `DWN` errors.
#[derive(Error, Debug, Deserialize)]
pub enum Error {
    /// Placeholder error type until moving to more strongly typed errors.
    #[error(r#"{{"code": 400, "detail": "{0}"}}"#)]
    Unexpected(String),

    /// The web node encountered an unexpected condition in a dependant library.
    #[error(r#"{{"code": 400, "detail": "{0}"}}"#)]
    Server(String),

    /// A required resource was not found.
    #[error(r#"{{"code": 401, "detail": "{0}"}}"#)]
    Unauthorized(String),

    /// A required resource was not found.
    #[error(r#"{{"code": 403, "detail": "{0}"}}"#)]
    Forbidden(String),

    /// A required resource was not found.
    #[error(r#"{{"code": 404, "detail": "{0}"}}"#)]
    NotFound(String),

    /// A database write conflict occurred.
    #[error(r#"{{"code": 409, "detail": "{0}"}}"#)]
    Conflict(String),

    /// A database write conflict occurred.
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

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: Base64Error) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(error: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(error: http::uri::InvalidUri) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<jsonschema::error::ValidationError<'_>> for Error {
    fn from(error: jsonschema::error::ValidationError<'_>) -> Self {
        Self::Server(error.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Server(error.to_string())
    }
}

// impl From<cid::Error> for Error {
//     fn from(error: cid::Error) -> Self {
//         Self::Server(error.to_string())
//     }
// }

impl From<libipld::cid::Error> for Error {
    fn from(error: libipld::cid::Error) -> Self {
        Self::Server(error.to_string())
    }
}

/// Construct an `Error::Unexpected` error from a string or existing error
/// value.
///
/// This evaluates to an [`Error`][crate::Error]. It can take either just a
/// string, or a format string with arguments. It also can take any custom type
/// which implements `Debug` and `Display`.
///
/// # Example
///
/// ```
/// # type V = ();
/// #
/// use crate::{unexpected, Result};
///
/// fn lookup(key: &str) -> Result<V> {
///     if key.len() != 16 {
///         return Err(unexpected!("key length must be 16 characters, got {:?}", key"));
///     }
///
///     // ...
///     # Ok(())
/// }
/// ```
#[macro_export]
macro_rules! unexpected {
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Unexpected(format!($fmt, $($arg)*))
    };
    // ($msg:literal $(,)?) => {
    //     $crate::Error::Unexpected($msg.into())
    // };
     ($err:expr $(,)?) => {
        $crate::Error::Unexpected(format!($err))
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
    use serde_json::{json, Value};

    use super::*;

    // Test that error details are retuned as json.
    #[test]
    fn err_json() {
        let err = Error::Unexpected("bad request".into());
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
