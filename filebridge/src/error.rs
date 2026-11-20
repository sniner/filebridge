//! Error types for the filebridge client.

use thiserror::Error;

/// Errors that can occur during filebridge operations.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP request failed.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// I/O error during streaming or file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// HMAC key setup failed.
    #[error("HMAC key error")]
    Hmac,

    /// Token required but not configured.
    #[error("token required for this operation")]
    TokenRequired,

    /// Response nonce did not match the request nonce.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// Server returned an error response.
    ///
    /// Status and message are always the server's; the client makes up
    /// neither. For a location with a token they come from the encrypted
    /// response and are authentic.
    #[error("API error: {0} - {1}")]
    Api(reqwest::StatusCode, String),

    /// The server's response does not fit the request, for example metadata
    /// where file content was asked for.
    ///
    /// For a location with a token the response is authentic: the server sent
    /// it in answer to this request. The usual cause is a server of another
    /// version.
    #[error("unexpected response from server: {0}")]
    Protocol(String),

    /// The system clock is set before 1970, so no request can be signed.
    #[error("system clock is set before 1970")]
    SystemClock,

    /// A location with a token answered with something other than an
    /// encrypted response.
    ///
    /// That is the case when the server rejects the request before it is
    /// authenticated (wrong token, clocks more than 30 seconds apart), when the
    /// server is older than 0.5, when a proxy answers in its place, and when
    /// the response was altered in transit. Status and text are what arrived
    /// and prove nothing about the outcome of the operation.
    #[error("unverified response from server: {0} - {1}")]
    Unverified(reqwest::StatusCode, String),

    /// The requested path is a directory, not a file.
    #[error("Target is a directory")]
    IsDirectory,

    /// URL parsing failed.
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    /// Base64 decoding failed.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Stream protocol error.
    #[error("Stream error: {0}")]
    Stream(#[from] crate::stream::StreamError),
}
