use http::uri::Uri;

use crate::{Result, unexpected};

pub fn clean_url(url: &str) -> Result<String> {
    let parsed = url.parse::<Uri>()?;

    let scheme = parsed.scheme().map_or_else(|| "http://".to_string(), |s| format!("{s}://"));
    let Some(authority) = parsed.authority() else {
        return Err(unexpected!("protocol URI ${url} must have an authority"));
    };
    let path = parsed.path().trim_end_matches('/');

    Ok(format!("{scheme}{authority}{path}"))
}

// pub fn validate_url(url: &str) -> Result<()> {
//     if url != clean_url(url)? {
//         return Err(anyhow!("protocol URI ${url} must be normalized"));
//     }
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scheme() {
        let url = "example.com";
        let cleaned = clean_url(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }

    #[test]
    fn trailing_slash() {
        let url = "http://example.com/";
        let cleaned = clean_url(url).expect("should clean");
        assert_eq!(cleaned, "http://example.com");
    }
}
