//! Encrypted request envelope: reading, decrypting, and dispatching token-mode requests.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};
use bytes::Bytes;
use hyper::body::Frame;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::error::ApiError;

use super::fs::{delete_file_inner, resolve_canonical_path};
use super::{AppState, FileQuery, ReceiverBody, put_file_inner};

/// Maximum size for encrypted request envelopes (`application/vnd.filebridge.request`).
///
/// This limit protects the three handlers that fully buffer the request body
/// before decryption: encrypted GET (file info / directory listing), encrypted
/// HEAD, and encrypted DELETE. These envelopes are small JSON payloads (path +
/// optional offset/length), so 64 KiB is far more than any legitimate envelope
/// will ever need.
///
/// Streaming file transfers (`vnd.filebridge.stream` and `application/octet-stream`)
/// are **not** subject to this limit — they write data to disk chunk by chunk and
/// their size is bounded only by the filesystem.
const MAX_ENVELOPE_SIZE: usize = 64 * 1024; // 64 KiB

/// Encrypted request envelope: path and parameters sent in body instead of URL (token-mode).
#[derive(Debug, Deserialize)]
pub(super) struct RequestEnvelope {
    pub path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
    #[serde(default)]
    pub extensive: bool,
}

/// Read a small request body, rejecting it if it exceeds `MAX_ENVELOPE_SIZE`.
pub(super) async fn collect_envelope(body: axum::body::Body) -> Result<bytes::Bytes, ApiError> {
    use http_body_util::BodyExt;
    let mut total = 0usize;
    let mut buf = bytes::BytesMut::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ApiError::BadRequest("frame read error".into()))?;
        if let Ok(data) = frame.into_data() {
            total += data.len();
            if total > MAX_ENVELOPE_SIZE {
                return Err(ApiError::PayloadTooLarge);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf.freeze())
}

/// Decrypt a request envelope from the body (used in token-mode when path is not in URL).
pub(super) fn decrypt_request_envelope(
    token: &str,
    sig: &str,
    body: &[u8],
) -> Result<RequestEnvelope, ApiError> {
    let body_str =
        std::str::from_utf8(body).map_err(|_| ApiError::BadRequest("invalid UTF-8 in body".into()))?;
    let json_bytes = filebridge::stream::decrypt_json_response(token, sig, body_str)
        .map_err(|e| ApiError::BadRequest(format!("envelope decryption failed: {e}")))?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid envelope JSON: {e}")))
}

pub async fn encrypted_head(
    Path(dir_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };
    let Some(token) = &entry.token else {
        return Err(ApiError::BadRequest("token required".into()));
    };
    let sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError::Unauthorized("missing X-Signature".into()))?;

    let body_bytes = collect_envelope(body).await?;
    let envelope = decrypt_request_envelope(token, sig, &body_bytes)?;
    tracing::info!("/{}", envelope.path);

    if !entry.allow_inspect {
        return Err(ApiError::Forbidden("inspect not allowed".into()));
    }

    resolve_canonical_path(entry, &envelope.path)?;
    Ok(StatusCode::OK)
}

pub async fn encrypted_put(
    Path(dir_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    mut body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };
    let Some(token) = &entry.token else {
        return Err(ApiError::BadRequest("token required".into()));
    };
    let sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError::Unauthorized("missing X-Signature".into()))?;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if content_type != "application/vnd.filebridge.stream" {
        return Err(ApiError::BadRequest("expected vnd.filebridge.stream content type".into()));
    }

    // For PUT with stream: first frame is META containing the encrypted envelope.
    // Read body chunks incrementally until the META frame is found, then stream the rest.
    use http_body_util::BodyExt;
    let mut decoder = filebridge::stream::StreamDecoder::new();
    let meta_payload;

    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    decoder.push(&data);
                    match decoder.next_frame() {
                        Ok(Some(filebridge::stream::StreamFrame::Meta { payload })) => {
                            meta_payload = payload;
                            break;
                        }
                        Ok(Some(_)) => {
                            return Err(ApiError::BadRequest("expected META frame first".into()))
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            return Err(ApiError::BadRequest(format!("stream decode: {e}")))
                        }
                    }
                }
            }
            Some(Err(e)) => {
                return Err(ApiError::BadRequest(format!("body read error: {e}")))
            }
            None => return Err(ApiError::BadRequest("EOF before META frame".into())),
        }
    }

    // Decrypt the META payload to get the request envelope
    let meta_str = std::str::from_utf8(&meta_payload)
        .map_err(|_| ApiError::BadRequest("META payload not UTF-8".into()))?;
    let json_bytes = filebridge::stream::decrypt_json_response(token, sig, meta_str)
        .map_err(|e| ApiError::BadRequest(format!("META decryption: {e}")))?;
    let envelope: RequestEnvelope = serde_json::from_slice(&json_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid META envelope: {e}")))?;
    tracing::info!("/{}", envelope.path);

    // Reconstruct remaining body: leftover bytes from decoder + rest of body stream
    let remaining_bytes = decoder.remaining().to_vec();
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(128);

    tokio::spawn(async move {
        if !remaining_bytes.is_empty()
            && tx
                .send(Ok(Frame::data(Bytes::from(remaining_bytes))))
                .await
                .is_err()
        {
            return;
        }
        while let Some(frame_res) = body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data()
                        && tx.send(Ok(Frame::data(data))).await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = tx
                        .send(Err(std::io::Error::other("body read error")))
                        .await;
                    break;
                }
            }
        }
    });

    let remaining_body = axum::body::Body::new(ReceiverBody { rx });

    let params = FileQuery {
        offset: envelope.offset,
        length: envelope.length,
        extensive: false,
    };

    put_file_inner(entry, &envelope.path, params, &headers, remaining_body).await
}

pub async fn encrypted_delete(
    Path(dir_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };
    let Some(token) = &entry.token else {
        return Err(ApiError::BadRequest("token required".into()));
    };
    let sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError::Unauthorized("missing X-Signature".into()))?;

    let body_bytes = collect_envelope(body).await?;
    let envelope = decrypt_request_envelope(token, sig, &body_bytes)?;
    tracing::info!("/{}", envelope.path);

    delete_file_inner(entry, &envelope.path, &state.hash_cache).await
}
