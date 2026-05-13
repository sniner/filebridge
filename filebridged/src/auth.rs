use crate::error::ApiError;
use crate::restapi::AppState;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Instrument;

type HmacSha256 = Hmac<Sha256>;

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let full_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let method = req.method().to_string();

    // Extract dir_id from path: /api/v1/fs/{dir_id}/...
    let path_str = req.uri().path();
    let parts: Vec<&str> = path_str.split('/').collect();
    if parts.len() < 5 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "fs" {
        return Ok(next.run(req).await);
    }

    let dir_id = parts[4];
    let Some(entry) = state.config.get_location(dir_id) else {
        return Ok(next.run(req).await);
    };

    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "-".to_string());
    let span = tracing::info_span!("request", %method, location = %entry.name, client = %client_ip);

    let Some(token) = &entry.token else {
        // No token configured, access is open
        return Ok(next.run(req).instrument(span).await);
    };

    // Authentication required
    let headers = req.headers();
    let signature_hex = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or(ApiError::Unauthorized("missing X-Signature".into()))?;

    let timestamp_str = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or(ApiError::Unauthorized("missing X-Timestamp".into()))?;

    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::Unauthorized("invalid timestamp".into()))?;

    let nonce_str = headers
        .get("X-Nonce")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or(ApiError::Unauthorized("missing X-Nonce".into()))?;

    // Check expiration (30 seconds)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("system clock before UNIX epoch")))?
        .as_secs();

    if now.abs_diff(timestamp) > 30 {
        return Err(ApiError::Unauthorized("timestamp expired".into()));
    }

    match state.nonce_validator.is_replay(&nonce_str) {
        Ok(true) => return Err(ApiError::Unauthorized("nonce replay".into())),
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("HMAC key setup failed")))?;

    mac.update(timestamp_str.as_bytes());
    mac.update(nonce_str.as_bytes());
    mac.update(method.as_bytes());
    mac.update(full_uri.as_bytes());

    let expected = mac.finalize().into_bytes();
    let sig_bytes =
        hex::decode(&signature_hex).map_err(|_| ApiError::Unauthorized("invalid signature hex".into()))?;

    if sig_bytes.len() != expected.len() {
        return Err(ApiError::Unauthorized("signature length mismatch".into()));
    }

    use subtle::ConstantTimeEq;
    if sig_bytes.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
        return Err(ApiError::Unauthorized("invalid signature".into()));
    }

    let mut response = next.run(req).instrument(span).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Nonce",
        axum::http::HeaderValue::from_str(&nonce_str)
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid nonce header value")))?,
    );

    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocationEntry;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tower::util::ServiceExt;

    fn mock_state(token: Option<String>) -> AppState {
        let mut locations = HashMap::new();
        locations.insert(
            "demo".to_string(),
            LocationEntry {
                name: "demo".to_string(),
                path: "/tmp".into(),
                allow_read: true,
                allow_create: true,
                allow_replace: true,
                allow_inspect: true,
                allow_delete: true,
                allow_recurse: true,
                allow_mkdir: false,
                token,
                #[cfg(unix)]
                file_permissions: None,
            },
        );
        AppState {
            config: Arc::new(crate::config::Config { locations }),
            nonce_validator: Arc::new(crate::nonce::NonceValidator::new()),
            hash_cache: Arc::new(crate::cache::HashCache::new()),
        }
    }

    #[tokio::test]
    async fn test_auth_middleware_valid() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route("/api/v1/fs/demo/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "1234567890abcdef";
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"GET");
        mac.update(b"/api/v1/fs/demo/test");
        let signature = hex::encode(mac.finalize().into_bytes());

        let req = Request::builder()
            .uri("/api/v1/fs/demo/test")
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_invalid_sig() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route("/api/v1/fs/demo/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);

        let req = Request::builder()
            .uri("/api/v1/fs/demo/test")
            .header("X-Signature", "wrong")
            .header("X-Timestamp", "1234567890")
            .header("X-Nonce", "1234567890abcdef")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_no_token_is_open() {
        let state = mock_state(None);
        let app = Router::new()
            .route("/api/v1/fs/demo/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);

        let req = Request::builder()
            .uri("/api/v1/fs/demo/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_expired() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route("/api/v1/fs/demo/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);

        let old_timestamp = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 40)
            .to_string();

        let req = Request::builder()
            .uri("/api/v1/fs/demo/test")
            .header("X-Signature", "any")
            .header("X-Timestamp", old_timestamp)
            .header("X-Nonce", "1234567890abcdef")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_query_params() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route("/api/v1/fs/demo/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "1234567890abcdef";
        let full_uri = "/api/v1/fs/demo/test?offset=100&length=50";

        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"GET");
        mac.update(full_uri.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let req = Request::builder()
            .uri(full_uri)
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
