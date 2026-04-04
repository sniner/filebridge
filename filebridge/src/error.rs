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
    #[error("API error: {0} - {1}")]
    Api(reqwest::StatusCode, String),

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
