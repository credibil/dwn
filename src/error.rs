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

    /// A database write conflict occurred.
    #[error(r#"{{"code": 409, "detail": "{0}"}}"#)]
    Conflict(String),

    /// The web node encountered an unexpected condition in a dependednt library.
    #[error(r#"{{"code": 400, "detail": "{0}"}}"#)]
    Server(String),
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
        Error::Server(error.to_string())
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: Base64Error) -> Self {
        Error::Server(error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Server(error.to_string())
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(error: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Server(error.to_string())
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error::Server(error.to_string())
    }
}

impl From<jsonschema::error::ValidationError<'_>> for Error {
    fn from(error: jsonschema::error::ValidationError<'_>) -> Self {
        Error::Server(error.to_string())
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
    ($msg:literal $(,)?) => {
        // $crate::__private::must_use({
        //     let error = $crate::__private::format_err($crate::__private::format_args!($msg"));
        //     error
        // })
        $crate::Error::Unexpected($msg.into())
    };
     ($err:expr $(,)?) => {
        // ({
        //     use $crate::__private::kind::*;
        //     let error = match $err {
        //         error => (&error).anyhow_kind().new(error),
        //     };
        //     error
        // })
        $crate::Error::Unexpected($err.into())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Unexpected(format!($fmt, $($arg)*))
    };
}

/// Error response for `OpenID` for Verifiable Credentials.
#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize)]
pub struct DwnError {
    /// Error code.
    pub code: u16,

    /// Error description.
    pub detail: String,
}

impl Error {
    /// Transfrom error to `OpenID` compatible json format.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::from_str(&self.to_string()).unwrap_or_default()
    }
}

// #[cfg(test)]
// mod test {
//     use serde_json::{json, Value};

//     use super::*;

//     // Test that error details are retuned as json.
//     #[test]
//     fn err_json() {
//         let err = Error::InvalidRequest("bad request".into());
//         let ser: Value = serde_json::from_str(&err.to_string()).unwrap();
//         assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
//     }

//     // Test that the error details are returned as an http query string.
//     #[test]
//     fn err_querystring() {
//         let err = Error::InvalidRequest("Invalid request description".into());
//         let ser = urlencode::to_string(&err).unwrap();
//         assert_eq!(ser, "error=invalid_request&error_description=Invalid%20request%20description");
//     }

//     // Test that the error details are returned as an http query string.
//     #[test]
//     fn err_serialize() {
//         let err = Error::InvalidRequest("bad request".into());
//         let ser = serde_json::to_value(&err).unwrap();
//         assert_eq!(ser, json!({"error":"invalid_request", "error_description": "bad request"}));
//     }

//     // Test an InvalidProof error returns c_nonce and c_nonce_expires_in values
//     // in the external response.
//     #[test]
//     fn proof_err() {
//         let err = Error::InvalidProof {
//             hint: "".into(),
//             c_nonce: "c_nonce".into(),
//             c_nonce_expires_in: 10,
//         };
//         let ser: Value = serde_json::from_str(&err.to_string()).unwrap();

//         assert_eq!(
//             ser,
//             json!({
//                 "error": "invalid_proof",
//                 "error_description": "",
//                 "c_nonce": "c_nonce",
//                 "c_nonce_expires_in": 10,
//             })
//         );
//     }
// }
