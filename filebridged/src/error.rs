use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("too many requests")]
    TooManyRequests,

    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

/// Body of every `500` response.
const INTERNAL_ERROR_BODY: &str = "internal error; see the filebridged log for the cause";

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // The cause of an internal error is built from io errors and the paths
        // they concern, absolute server paths among them, and this body is
        // sent unencrypted even for a token-protected location. The cause is
        // written to the log only.
        let body = if let ApiError::Internal(e) = &self {
            tracing::error!("{status}: {e:#}");
            INTERNAL_ERROR_BODY.to_owned()
        } else {
            tracing::warn!("{status}: {self}");
            self.to_string()
        };

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn internal_error_body_omits_the_cause() {
        let err = ApiError::Internal(anyhow::anyhow!(
            "chown(\"/srv/share/reports/q3.txt\", Some(0), None): Operation not permitted"
        ));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, INTERNAL_ERROR_BODY.as_bytes());
    }

    #[tokio::test]
    async fn other_errors_keep_their_message() {
        let resp = ApiError::Forbidden("read not allowed".into()).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "read not allowed".as_bytes());
    }
}
