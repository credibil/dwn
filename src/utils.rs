use url::Url;

use crate::Result;

pub fn clean_url(url: &str) -> Result<String> {
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        &format!("http://{url}")
    };

    let parsed = Url::parse(url)?;
    let cleaned = parsed.origin().ascii_serialization() + parsed.path();

    Ok(cleaned.trim_end_matches('/').to_owned())
}

// pub fn validate_url(url: &str) -> Result<()> {
//     if url != clean_url(url)? {
//         return Err(anyhow!("protocol URI ${url} must be normalized"));
//     }
//     Ok(())
// }
