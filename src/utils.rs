use anyhow::Result;
use url::Url;

pub fn clean_url(url: &str) -> Result<String> {
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        &format!("http://{url}")
    };

    let p = Url::parse(url)?;
    Ok(p.origin().ascii_serialization() + p.path())
}

// pub fn validate_url(url: &str) -> Result<()> {
//     if url != clean_url(url)? {
//         return Err(anyhow!("protocol URI ${url} must be normalized"));
//     }
//     Ok(())
// }
