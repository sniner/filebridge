use crate::location::FileBridgeLocation;
use url::Url;

/// HTTP client for a Filebridge server.
///
/// Holds the base URL and a shared HTTP client. Use [`location`](Self::location)
/// to obtain a [`FileBridgeLocation`] handle for a specific shared directory.
pub struct FileBridgeClient {
    pub(crate) base_url: Url,
    pub(crate) client: reqwest::Client,
}

impl FileBridgeClient {
    /// Creates a new client for the given server base URL.
    ///
    /// The URL should point to the server root (e.g. `http://localhost:8000`).
    /// Trailing slashes are stripped automatically.
    pub fn new(base_url: &str) -> Result<Self, url::ParseError> {
        let base_url = Url::parse(base_url.trim_end_matches('/'))?;
        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }

    /// Returns a [`FileBridgeLocation`] handle for the given directory ID.
    ///
    /// If `token` is provided, all requests through this location will be
    /// HMAC-signed and file content will be encrypted end-to-end.
    pub fn location(&self, dir_id: &str, token: Option<String>) -> FileBridgeLocation<'_> {
        FileBridgeLocation::new(self, dir_id, token)
    }
}
