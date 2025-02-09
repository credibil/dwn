//! URI utilities.

use http::uri::Uri;

use crate::{Result, unexpected};

pub fn clean(uri: &str) -> Result<String> {
    let stripped = uri.strip_suffix('/').unwrap_or(uri);
    let parsed = stripped.parse::<Uri>()?;

    let scheme = parsed.scheme().map_or_else(|| "http://".to_string(), |s| format!("{s}://"));
    let Some(authority) = parsed.authority() else {
        return Err(unexpected!("protocol URI {uri} must have an authority"));
    };
    let path = parsed.path().trim_end_matches('/');

    Ok(format!("{scheme}{authority}{path}"))
}

#[cfg(feature = "server")]
pub fn validate(uri: &str) -> Result<()> {
    uri.parse::<Uri>().map_or_else(|_| Err(unexpected!("invalid URL: {uri}")), |_| Ok(()))
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
