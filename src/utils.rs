// use url::Url;
use http::uri::Uri;

use crate::{unexpected, Result};

pub fn clean_url(url: &str) -> Result<String> {
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        &format!("http://{url}")
    };

    let parsed: Uri = url.parse()?;
    let Some(authority) = parsed.authority() else {
        return Err(unexpected!("protocol URI ${url} must have an authority"));
    };

    let cleaned = format!("{authority}{path}", path = parsed.path());
    Ok(cleaned.trim_end_matches('/').to_owned())
}

// pub fn validate_url(url: &str) -> Result<()> {
//     if url != clean_url(url)? {
//         return Err(anyhow!("protocol URI ${url} must be normalized"));
//     }
//     Ok(())
// }
