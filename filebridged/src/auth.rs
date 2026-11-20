use crate::error::ApiError;
use crate::restapi::AppState;
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Instrument;

type HmacSha256 = Hmac<Sha256>;

/// Maximum tolerated difference between the request's `X-Timestamp` and the
/// server clock, in seconds. A timestamp `T` is accepted while the server clock
/// lies in `[T - MAX, T + MAX]`, i.e. a window `2 * MAX` seconds wide. The nonce
/// cache TTL must be at least this wide to fully cover the replay window
/// (see `nonce::NONCE_TTL_SECS`).
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 30;

/// Marks a response as an encrypted file stream.
///
/// [`auth_middleware`] encrypts every response of a token-protected location
/// that does not carry this extension.
#[derive(Clone)]
pub struct EncryptedStream;

/// Authenticates requests to a location with a token and encrypts the
/// responses to them.
///
/// Must be installed with `route_layer`, so that it runs after routing and
/// sees the path parameters of the matched route.
pub async fn auth_middleware(
    State(state): State<AppState>,
    Path(params): Path<Vec<(String, String)>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let full_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let method = req.method().to_string();

    // The location name has to come from the same extractor the handlers
    // use. A URL can spell one name in several ways (`a` and `%61`), and a
    // lookup by the raw path segment would miss the location that the handler
    // then finds under the decoded name.
    let Some((_, dir_id)) = params.iter().find(|(name, _)| name == "dir_id") else {
        return Ok(next.run(req).await);
    };
    let path_in_url = params
        .iter()
        .any(|(name, value)| name != "dir_id" && !value.is_empty());
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
        // No token configured, access is open. A signed request comes from a
        // client that holds a token for this location and expects a signed,
        // encrypted answer; answering it in the clear would leave the client
        // to find out from a response it cannot verify.
        if req.headers().contains_key("X-Signature") {
            return Err(ApiError::BadRequest(
                "location has no token; send requests to it without one".into(),
            ));
        }
        return Ok(next.run(req).instrument(span).await);
    };

    // The status of a token-mode operation is in the encrypted response body,
    // and a HEAD response has none. Answering HEAD would leave the client with
    // the `200` of the status line whatever the outcome.
    if req.method() == axum::http::Method::HEAD {
        return Err(ApiError::MethodNotAllowed(
            "HEAD is not available for a location with a token".into(),
        ));
    }

    let Authenticated { signature, nonce } =
        authenticate(&state, token, req.headers(), &method, &full_uri)?;

    // From here on the request is authenticated and its nonce is claimed, so
    // exactly one response is encrypted under the keys derived from this
    // signature. The errors above are sent as plain text: a rejected request
    // has no usable key, and a replayed one would get a second message under
    // a key and nonce that are already used.
    let response = if path_in_url {
        ApiError::BadRequest(
            "location has a token; send the path in the encrypted request, not in the URL".into(),
        )
        .into_response()
    } else {
        next.run(req).instrument(span).await
    };
    let mut response = encrypt_response(token, &signature, response).await;

    let headers = response.headers_mut();
    headers.insert(
        "X-Nonce",
        axum::http::HeaderValue::from_str(&nonce)
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid nonce header value")))?,
    );

    Ok(response)
}

/// What an authenticated request leaves for its response: the signature the
/// response keys are derived from, and the nonce the response repeats.
struct Authenticated {
    signature: String,
    nonce: String,
}

/// The value of a header that every signed request has.
fn signed_header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::Unauthorized(format!("missing {name}")))
}

/// Checks that a request to a location with `token` is signed with that
/// token, is not older than the allowed clock skew and has not been seen
/// before. Claims the nonce of a request that passes.
fn authenticate(
    state: &AppState,
    token: &str,
    headers: &HeaderMap,
    method: &str,
    full_uri: &str,
) -> Result<Authenticated, ApiError> {
    use subtle::ConstantTimeEq;

    let signature = signed_header(headers, "X-Signature")?;
    let timestamp_str = signed_header(headers, "X-Timestamp")?;
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::Unauthorized("invalid timestamp".into()))?;
    let nonce = signed_header(headers, "X-Nonce")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("system clock before UNIX epoch")))?
        .as_secs();
    if now.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
        return Err(ApiError::Unauthorized("timestamp expired".into()));
    }

    // Verify the HMAC signature BEFORE touching the nonce cache. Consuming a
    // nonce slot for an unverified request would let an unauthenticated client
    // flood the cache and trip the capacity limit, denying service to everyone.
    let expected =
        filebridge::stream::request_signature(token, &timestamp_str, &nonce, method, full_uri)
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("HMAC key setup failed")))?;
    // The response keys are derived from the signature as the client wrote
    // it. Upper-case hex is the same signature in another spelling and would
    // give the same request a second set of keys.
    if signature.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ApiError::Unauthorized("invalid signature hex".into()));
    }
    let sig_bytes = hex::decode(&signature)
        .map_err(|_| ApiError::Unauthorized("invalid signature hex".into()))?;

    if sig_bytes.len() != expected.len() {
        return Err(ApiError::Unauthorized("signature length mismatch".into()));
    }

    if sig_bytes.ct_eq(expected.as_slice()).unwrap_u8() != 1 {
        let legacy = legacy_signature(token, &timestamp_str, &nonce, method, full_uri)?;
        if sig_bytes.ct_eq(legacy.as_slice()).unwrap_u8() == 1 {
            return Err(ApiError::Unauthorized(
                "this client uses the token mode of filebridge 0.4 or earlier; \
                 update it to 0.5 or later"
                    .into(),
            ));
        }
        return Err(ApiError::Unauthorized("invalid signature".into()));
    }

    // Signature is valid: only now claim the nonce to reject replays.
    if state.nonce_validator.is_replay(&nonce)? {
        return Err(ApiError::Unauthorized("nonce replay".into()));
    }
    Ok(Authenticated { signature, nonce })
}

/// The request signature as filebridge 0.4 and earlier computed it. Only used
/// to tell such a client what is wrong.
fn legacy_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> Result<[u8; 32], ApiError> {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("HMAC key setup failed")))?;
    mac.update(timestamp.as_bytes());
    mac.update(nonce.as_bytes());
    mac.update(method.as_bytes());
    mac.update(uri.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Turn the response of a handler into the response a token-protected location
/// sends: status `200` and a body that holds the handler's status and body,
/// encrypted. An encrypted file stream is passed through as it is.
///
/// The handler's headers are dropped, so the handler cannot put anything about
/// the result outside the encrypted body.
async fn encrypt_response(token: &str, signature: &str, response: Response) -> Response {
    if response.extensions().get::<EncryptedStream>().is_some() {
        return response;
    }

    let status = response.status();
    let body = match axum::body::to_bytes(response.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(e) => {
            return ApiError::Internal(anyhow::anyhow!("read response body: {e}")).into_response();
        }
    };

    let reply = if status.is_success() {
        let body = if body.is_empty() {
            None
        } else {
            match serde_json::from_slice(&body) {
                Ok(value) => Some(value),
                Err(e) => {
                    return ApiError::Internal(anyhow::anyhow!(
                        "response of a token location is neither JSON nor a stream: {e}"
                    ))
                    .into_response();
                }
            }
        };
        filebridge::stream::Reply {
            status: status.as_u16(),
            error: None,
            body,
        }
    } else {
        filebridge::stream::Reply {
            status: status.as_u16(),
            error: Some(String::from_utf8_lossy(&body).into_owned()),
            body: None,
        }
    };

    match filebridge::stream::seal_reply(token, signature, &reply) {
        Ok(sealed) => (
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            )],
            sealed,
        )
            .into_response(),
        Err(e) => ApiError::Internal(anyhow::anyhow!("response encryption: {e}")).into_response(),
    }
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
                fsync: false,
                token,
                #[cfg(unix)]
                file_permissions: None,
                #[cfg(unix)]
                dir_permissions: None,
            },
        );
        AppState {
            config: Arc::new(crate::config::Config { locations }),
            nonce_validator: Arc::new(crate::nonce::NonceValidator::new()),
            hash_cache: Arc::new(crate::cache::HashCache::new()),
        }
    }

    const BASE: &str = "/api/v1/fs/demo";
    const BASE_ROUTE: &str = "/api/v1/fs/{dir_id}";

    async fn ok() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({"ok": true}))
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route(BASE_ROUTE, get(ok))
            .route("/api/v1/fs/{dir_id}/{*path}", get(ok))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state)
    }

    fn now() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn sign(method: &str, uri: &str, timestamp: &str, nonce: &str) -> String {
        hex::encode(
            filebridge::stream::request_signature("secret", timestamp, nonce, method, uri).unwrap(),
        )
    }

    fn request(
        method: &str,
        uri: &str,
        signature: &str,
        timestamp: &str,
        nonce: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::empty())
            .unwrap()
    }

    async fn body_text(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&body).into_owned()
    }

    /// Decrypts a response that must be an encrypted reply with status line 200.
    async fn open(response: Response, signature: &str) -> filebridge::stream::Reply {
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        filebridge::stream::open_reply("secret", signature, &body).unwrap()
    }

    #[tokio::test]
    async fn test_auth_middleware_valid() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.headers().get("X-Nonce").unwrap(), nonce);

        let reply = open(response, &signature).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.error, None);
        assert_eq!(reply.body, Some(serde_json::json!({"ok": true})));
    }

    #[tokio::test]
    async fn test_auth_middleware_invalid_sig() {
        let app = app(mock_state(Some("secret".to_string())));

        let response = app
            .oneshot(request(
                "GET",
                BASE,
                "wrong",
                "1234567890",
                "1234567890abcdef",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_errors_are_plain_text() {
        // A request that fails authentication has no key its response could be
        // encrypted with.
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();

        let response = app
            .oneshot(request(
                "GET",
                BASE,
                &"00".repeat(32),
                &timestamp,
                "1234567890abcdef",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(response).await, "invalid signature");
    }

    #[tokio::test]
    async fn test_signature_of_an_older_client_is_named() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature =
            hex::encode(legacy_signature("secret", &timestamp, nonce, "GET", BASE).unwrap());

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            body_text(response)
                .await
                .contains("filebridge 0.4 or earlier")
        );
    }

    #[tokio::test]
    async fn test_replay_is_refused_in_plain_text() {
        // The first response used the key and nonce derived from this
        // signature. A second encrypted message under them would break both.
        let state = mock_state(Some("secret".to_string()));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let first = app(state.clone())
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(open(first, &signature).await.status, 200);

        let second = app(state)
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(second).await, "nonce replay");
    }

    #[tokio::test]
    async fn test_token_location_refuses_head() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("HEAD", BASE, &timestamp, nonce);

        let response = app
            .oneshot(request("HEAD", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_token_location_refuses_path_in_url() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let uri = "/api/v1/fs/demo/reports/q3.txt";
        let signature = sign("GET", uri, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", uri, &signature, &timestamp, nonce))
            .await
            .unwrap();
        let reply = open(response, &signature).await;
        assert_eq!(reply.status, 400);
        assert!(reply.error.unwrap().contains("not in the URL"));
        assert_eq!(reply.body, None);
    }

    #[tokio::test]
    async fn test_handler_headers_are_dropped() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route(
                BASE_ROUTE,
                get(|| async { ([("X-File-MDate", "2031-01-01T00:00:00Z")], ok().await) }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert!(response.headers().get("X-File-MDate").is_none());
        assert_eq!(open(response, &signature).await.status, 200);
    }

    #[tokio::test]
    async fn test_encrypted_stream_is_passed_through() {
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route(
                BASE_ROUTE,
                get(|| async {
                    let mut response = "frames".into_response();
                    response.extensions_mut().insert(EncryptedStream);
                    response
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "frames");
    }

    #[tokio::test]
    async fn test_unmarked_non_json_response_is_not_sent() {
        // A handler that returns anything but JSON or a marked stream for a
        // token location has a bug. Its body must not go out unencrypted.
        let state = mock_state(Some("secret".to_string()));
        let app = Router::new()
            .route(BASE_ROUTE, get(|| async { "file content" }))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .with_state(state);
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body_text(response).await.contains("file content"));
    }

    #[tokio::test]
    async fn test_auth_middleware_no_token_is_open() {
        let app = app(mock_state(None));

        let req = Request::builder().uri(BASE).body(Body::empty()).unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn test_auth_middleware_no_token_refuses_signed_request() {
        let app = app(mock_state(None));

        let response = app
            .oneshot(request("GET", BASE, "00", "1234567890", "1234567890abcdef"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(response).await.contains("has no token"));
    }

    #[tokio::test]
    async fn test_auth_middleware_expired() {
        let app = app(mock_state(Some("secret".to_string())));
        let old_timestamp = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 40)
            .to_string();

        let response = app
            .oneshot(request(
                "GET",
                BASE,
                "any",
                &old_timestamp,
                "1234567890abcdef",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_signature_does_not_consume_nonce() {
        // H1: a request that fails signature verification must not claim the
        // nonce, otherwise the same nonce stays usable for the legitimate caller.
        let state = mock_state(Some("secret".to_string()));
        let timestamp = now();
        let nonce = "deadbeefcafef00d";

        // First: forged signature, valid timestamp + nonce.
        let resp = app(state.clone())
            .oneshot(request("GET", BASE, "00", &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Then: the genuine caller reuses the same nonce with a valid signature.
        let signature = sign("GET", BASE, &timestamp, nonce);
        let resp = app(state)
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(open(resp, &signature).await.status, 200);
    }

    #[tokio::test]
    async fn test_auth_middleware_query_params() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let full_uri = "/api/v1/fs/demo?extensive=true";
        let signature = sign("GET", full_uri, &timestamp, nonce);

        let response = app
            .oneshot(request("GET", full_uri, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(open(response, &signature).await.status, 200);
    }

    #[tokio::test]
    async fn test_percent_encoded_location_name_is_authenticated() {
        // `dem%6f` is the location `demo` to the handler, so it has to be the
        // location `demo` here as well.
        let app = app(mock_state(Some("secret".to_string())));

        let req = Request::builder()
            .uri("/api/v1/fs/dem%6f")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_signature_does_not_fit_a_second_request() {
        // Every key of an exchange is derived from the signature alone, so a
        // signature must stand for exactly one request. Without separators in
        // the signed data, moving a character from the nonce to the method
        // gave a different request with the same signature and a nonce that
        // had not been seen: a second response under the same key and nonce.
        let state = mock_state(Some("secret".to_string()));
        let timestamp = now();
        let nonce = "0011223344556677";
        let signature = sign("GET", BASE, &timestamp, nonce);

        let first = app(state.clone())
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(open(first, &signature).await.status, 200);

        let second = app(state)
            .oneshot(request(
                "7GET",
                BASE,
                &signature,
                &timestamp,
                "001122334455667",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(second).await, "invalid signature");
    }

    #[tokio::test]
    async fn test_upper_case_signature_is_refused() {
        let app = app(mock_state(Some("secret".to_string())));
        let timestamp = now();
        let nonce = "1234567890abcdef";
        let signature = sign("GET", BASE, &timestamp, nonce).to_uppercase();

        let response = app
            .oneshot(request("GET", BASE, &signature, &timestamp, nonce))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
