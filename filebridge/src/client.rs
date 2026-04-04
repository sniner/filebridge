use std::time::Duration;

use crate::error::Error;
use crate::location::FileBridgeLocation;
use url::Url;

/// Default HTTP timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Trailing slashes are stripped automatically. Uses a default timeout of
    /// 30 seconds; use [`with_timeout`](Self::with_timeout) to override.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT)
    }

    /// Creates a new client with a custom request timeout.
    ///
    /// The timeout applies to each individual HTTP request.
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Result<Self, Error> {
        let base_url = Url::parse(base_url.trim_end_matches('/'))?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()?;
        Ok(Self { base_url, client })
    }

    /// Returns a [`FileBridgeLocation`] handle for the given directory ID.
    ///
    /// If `token` is provided, all requests through this location will be
    /// HMAC-signed and file content will be encrypted end-to-end.
    pub fn location(&self, dir_id: &str, token: Option<String>) -> FileBridgeLocation<'_> {
        FileBridgeLocation::new(self, dir_id, token)
    }
}
