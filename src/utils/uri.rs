//! URI utilities.

use anyhow::Context;
use http::uri::Uri;

use crate::error::bad_request;
use crate::handlers::Result;

pub(crate) fn clean(uri: &str) -> Result<String> {
    let stripped = uri.strip_suffix('/').unwrap_or(uri);
    let parsed = stripped.parse::<Uri>().context("parsing URL")?;

    let scheme = parsed.scheme().map_or_else(|| "http://".to_string(), |s| format!("{s}://"));
    let Some(authority) = parsed.authority() else {
        return Err(bad_request!("protocol URI {uri} must have an authority"));
    };
    let path = parsed.path().trim_end_matches('/');

    Ok(format!("{scheme}{authority}{path}"))
}

#[cfg(feature = "server")]
pub(crate) fn validate(uri: &str) -> Result<()> {
    uri.parse::<Uri>().map_or_else(|_| Err(bad_request!("invalid URL: {uri}")), |_| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scheme() {
        let url = "example.com/";
        let cleaned = clean(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }

    #[test]
    fn trailing_slash() {
        let url = "http://example.com/";
        let cleaned = clean(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }
}
