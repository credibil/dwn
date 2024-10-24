use anyhow::Result;
use url::Url;

pub fn clean_url(url: &str) -> Result<String> {
    let uri = Url::parse(url)?;
    Ok(uri.origin().ascii_serialization() + uri.path())
}
