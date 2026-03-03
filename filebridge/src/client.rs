use crate::location::FileBridgeLocation;
use url::Url;

pub struct FileBridgeClient {
    pub(crate) base_url: Url,
    pub(crate) client: reqwest::Client,
}

impl FileBridgeClient {
    pub fn new(base_url: &str) -> Result<Self, url::ParseError> {
        let base_url = Url::parse(base_url.trim_end_matches('/'))?;
        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }

    pub fn location(&self, dir_id: &str, token: Option<String>) -> FileBridgeLocation<'_> {
        FileBridgeLocation::new(self, dir_id, token)
    }
}
