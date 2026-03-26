use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HMAC error")]
    Hmac,

    #[error("API error: {0} - {1}")]
    Api(reqwest::StatusCode, String),
    #[error("Target is a directory")]
    IsDirectory,

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Stream error: {0}")]
    Stream(#[from] crate::stream::StreamError),
}
