use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, head, put},
};
use bytes::Bytes;
use chrono::DateTime;
use hyper::body::{Body, Frame};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::config::LocationEntry;
use crate::error::ApiError;

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

/// Read a small request body, rejecting it if it exceeds `MAX_ENVELOPE_SIZE`.
async fn collect_envelope(body: axum::body::Body) -> Result<bytes::Bytes, ApiError> {
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
use crate::models::FileInfo;
use std::path::PathBuf;

fn resolve_canonical_write(
    entry: &LocationEntry,
    filepath: &str,
) -> Result<PathBuf, ApiError> {
    let full = entry.path.join(filepath);
    let parent = full.parent().ok_or(ApiError::Forbidden("no parent directory".into()))?;
    let canon_parent = parent
        .canonicalize()
        .map_err(|_| ApiError::Forbidden("path canonicalization failed".into()))?;
    if !canon_parent.starts_with(&entry.path)
        || (!entry.allow_recurse && canon_parent != entry.path)
    {
        return Err(ApiError::Forbidden("path outside allowed directory".into()));
    }
    let file_name = full
        .file_name()
        .ok_or(ApiError::Forbidden("no filename".into()))?;
    let target = canon_parent.join(file_name);
    // Reject if the target is an existing symlink (could point outside the allowed directory)
    if target.is_symlink() {
        return Err(ApiError::Forbidden("symlink rejected".into()));
    }
    Ok(target)
}

/// Open a file for writing atomically, respecting allow_create/allow_replace permissions.
/// Returns the file handle and whether the file was newly created.
async fn open_for_write(
    fpath: &std::path::Path,
    entry: &LocationEntry,
    truncate: bool,
) -> Result<(tokio::fs::File, bool), ApiError> {
    if entry.allow_create {
        // Try create_new first to atomically check existence
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fpath)
            .await
        {
            Ok(f) => return Ok((f, true)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !entry.allow_replace {
                    return Err(ApiError::Forbidden("file exists, replace not allowed".into()));
                }
                let f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(truncate)
                    .open(fpath)
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("open for write: {e}")))?;
                return Ok((f, false));
            }
            Err(e) => {
                return Err(ApiError::Internal(anyhow::anyhow!("create file: {e}")))
            }
        }
    }

    if entry.allow_replace {
        match tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(truncate)
            .open(fpath)
            .await
        {
            Ok(f) => Ok((f, false)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ApiError::Forbidden("file not found, create not allowed".into()))
            }
            Err(e) => Err(ApiError::Internal(anyhow::anyhow!("open for write: {e}"))),
        }
    } else {
        Err(ApiError::Forbidden("write not allowed".into()))
    }
}

fn resolve_canonical_path(entry: &LocationEntry, filepath: &str) -> Result<PathBuf, ApiError> {
    let full = entry.path.join(filepath);
    let canon = full
        .canonicalize()
        .map_err(|_| ApiError::NotFound(format!("path not found: {filepath}")))?;
    if !canon.starts_with(&entry.path)
        || (!entry.allow_recurse
            && canon != entry.path
            && canon.parent() != Some(entry.path.as_path()))
    {
        return Err(ApiError::Forbidden("path outside allowed directory".into()));
    }
    Ok(canon)
}

#[derive(Debug, Deserialize)]
pub struct ListParams {}


#[derive(Deserialize)]
pub struct FileQuery {
    pub offset: Option<u64>,
    pub length: Option<u64>,
    #[serde(default)]
    pub extensive: bool,
}

/// Encrypted request envelope: path and parameters sent in body instead of URL (token-mode).
#[derive(Debug, Deserialize)]
struct RequestEnvelope {
    path: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    extensive: bool,
}

/// Decrypt a request envelope from the body (used in token-mode when path is not in URL).
fn decrypt_request_envelope(
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

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub nonce_validator: Arc<crate::nonce::NonceValidator>,
    pub hash_cache: Arc<crate::cache::HashCache>,
}

struct ReceiverBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, std::io::Error>>,
}

impl Body for ReceiverBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

pub fn routes(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
        nonce_validator: Arc::new(crate::nonce::NonceValidator::new()),
        hash_cache: Arc::new(crate::cache::HashCache::new()),
    };

    Router::new()
        .route(
            "/api/v1/fs/{dir_id}",
            get(get_dir)
                .head(encrypted_head)
                .put(encrypted_put)
                .delete(encrypted_delete),
        )
        .route("/api/v1/fs/{dir_id}/", get(get_dir))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", get(get_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", head(has_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", put(put_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", delete(delete_file))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_middleware,
        ))
        .with_state(state)
}

fn json_response(
    entry: &LocationEntry,
    sig: &str,
    value: &serde_json::Value,
) -> Result<Response, ApiError> {
    if let Some(token) = &entry.token {
        let json_bytes = serde_json::to_vec(value)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("JSON serialization: {e}")))?;
        let encoded = filebridge::stream::encrypt_json_response(token, sig, &json_bytes)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("response encryption: {e}")))?;
        return Ok(Json(serde_json::json!({"message": encoded})).into_response());
    }
    Ok(Json(value.clone()).into_response())
}

async fn get_dir(
    Path(dir_id): Path<String>,
    Query(_params): Query<ListParams>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> Result<Response, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Ok(
            Json(serde_json::json!({"items": [], "detail": "Unknown directory ID"}))
                .into_response(),
        );
    };

    let sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Encrypted request: path in body instead of URL
    if content_type == "application/vnd.filebridge.request" {
        let token = entry
            .token
            .as_deref()
            .ok_or(ApiError::BadRequest("token required for encrypted request".into()))?;
        let body_bytes = collect_envelope(body).await?;
        let envelope = decrypt_request_envelope(token, sig, &body_bytes)?;
        let params = FileQuery {
            offset: envelope.offset,
            length: envelope.length,
            extensive: envelope.extensive,
        };
        return get_file_inner(entry, &envelope.path, params, &headers, sig, &state.hash_cache)
            .await;
    }

    if !entry.allow_inspect {
        return json_response(
            entry,
            sig,
            &serde_json::json!({"items": [], "detail": "Directory content hidden"}),
        );
    }

    match list_directory(&entry.path, entry.allow_recurse) {
        Ok(files) => json_response(entry, sig, &serde_json::json!({"items": files})),
        Err(_) => json_response(
            entry,
            sig,
            &serde_json::json!({"items": [], "detail": "Error reading directory"}),
        ),
    }
}

fn list_directory(path: &std::path::Path, allow_recurse: bool) -> Result<Vec<FileInfo>, ()> {
    let entries = path.read_dir().map_err(|_| ())?;
    let mut files = vec![];

    for entry in entries.flatten() {
        if let Ok(ft) = entry.file_type() {
            // Skip symlinks to prevent directory escapes
            if ft.is_symlink() {
                continue;
            }
            let is_dir = ft.is_dir();
            if !is_dir && !ft.is_file() {
                continue;
            }
            if is_dir && !allow_recurse {
                continue;
            }

            if let Some(name) = entry.file_name().to_str() {
                let (size, mtime) = if is_dir {
                    (None, None)
                } else {
                    match entry.metadata() {
                        Ok(meta) => {
                            let size = Some(meta.len());
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|mt| mt.duration_since(SystemTime::UNIX_EPOCH).ok())
                                .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
                                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                            (size, mtime)
                        }
                        Err(_) => (None, None),
                    }
                };
                files.push(FileInfo {
                    name: name.to_string(),
                    is_dir,
                    size,
                    mtime,
                    sha256: None,
                });
            }
        }
    }
    Ok(files)
}

async fn has_file(
    Path((dir_id, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    if !entry.allow_inspect {
        return Err(ApiError::Forbidden("inspect not allowed".into()));
    }

    resolve_canonical_path(entry, &filename)?;
    Ok(StatusCode::OK)
}

async fn get_file(
    Path((dir_id, filepath)): Path<(String, String)>,
    Query(params): Query<FileQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    let req_sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    get_file_inner(entry, &filepath, params, &headers, req_sig, &state.hash_cache).await
}

async fn get_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    headers: &HeaderMap,
    req_sig: &str,
    hash_cache: &crate::cache::HashCache,
) -> Result<Response, ApiError> {
    if !entry.allow_read {
        return Err(ApiError::Forbidden("read not allowed".into()));
    }

    tracing::debug!("candidate path = {:?}", entry.path.join(filepath));

    let path = resolve_canonical_path(entry, filepath)?;

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(_) => return Err(ApiError::NotFound(format!("file not found: {filepath}"))),
    };

    if metadata.is_dir() {
        if path != entry.path && !entry.allow_recurse {
            return Err(ApiError::Forbidden("recurse not allowed".into()));
        }
        if !entry.allow_inspect {
            return Err(ApiError::Forbidden("inspect not allowed".into()));
        }

        match list_directory(&path, entry.allow_recurse) {
            Ok(files) => {
                return json_response(entry, req_sig, &serde_json::json!({"items": files}));
            }
            Err(_) => {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "failed to list directory: {filepath}"
                )))
            }
        }
    }

    let wants_octet_stream = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim() == "application/octet-stream"))
        .unwrap_or(false);

    let wants_stream = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .any(|p| p.trim() == "application/vnd.filebridge.stream")
        })
        .unwrap_or(false);

    let file_size = metadata.len();
    let current_offset = params.offset.unwrap_or(0);

    let mtime = metadata
        .modified()
        .ok()
        .and_then(|mtime| mtime.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

    if wants_stream {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| ApiError::NotFound(format!("open file: {e}")))?;

        if current_offset > 0 {
            file.seek(std::io::SeekFrom::Start(current_offset))
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("seek: {e}")))?;
        }

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.filebridge.stream"),
        );
        if let Some(mt) = &mtime {
            resp_headers.insert(
                "X-File-MDate",
                mt.parse()
                    .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid mtime header")))?,
            );
        }
        resp_headers.insert("X-File-Exists", HeaderValue::from_static("true"));

        let length_to_read = params
            .length
            .unwrap_or(file_size.saturating_sub(current_offset));

        // Calculate exact Content-Length for the StreamAead frames
        let mut total_length = 0u64;
        let mut rem = length_to_read;
        while rem > 0 {
            let chunk_size = rem.min(64 * 1024);
            total_length += 8 + chunk_size + 16; // DATA tag(4) + len(4) + payload + MAC(16)
            rem -= chunk_size;
        }
        total_length += 40; // STOP tag(4) + len(4) + hex_sig(32)
        resp_headers.insert(
            header::CONTENT_LENGTH,
            total_length
                .to_string()
                .parse()
                .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid content-length")))?,
        );

        let (tx, rx) = mpsc::channel(128);
        let token_opt = entry.token.clone();
        let req_sig_owned = req_sig.to_owned();

        tokio::spawn(async move {
            const STREAM_CHUNK_SIZE: usize = 64 * 1024;
            let mut remaining = length_to_read;
            let mut buf = vec![0; STREAM_CHUNK_SIZE];
            let req_sig_clone = req_sig_owned;
            let mut aead = token_opt.clone().and_then(|t| {
                if req_sig_clone.is_empty() {
                    None
                } else {
                    filebridge::stream::StreamAead::new(&t, &req_sig_clone).ok()
                }
            });
            let mut chunk: Vec<u8> = Vec::with_capacity(STREAM_CHUNK_SIZE + 16 + 1);

            loop {
                if remaining == 0 {
                    let stop_sig = aead.as_mut().and_then(|a| a.finalize().ok());
                    let frame = filebridge::stream::encode_stop(stop_sig.as_deref());
                    let _ = tx.send(Ok(Frame::data(Bytes::from(frame)))).await;
                    break;
                }

                let to_read = (buf.len() as u64).min(remaining) as usize;
                match file.read_exact(&mut buf[..to_read]).await {
                    Ok(_) => {
                        remaining -= to_read as u64;

                        chunk.clear();
                        chunk.extend_from_slice(&buf[..to_read]);
                        if let Some(ref mut a) = aead
                            && a.encrypt(&mut chunk).is_err()
                        {
                            let _ = tx
                                .send(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Encryption failed",
                                )))
                                .await;
                            break;
                        }

                        // DATA frame
                        let frame = filebridge::stream::encode_data(&chunk);

                        if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        let body = ReceiverBody { rx };
        return Ok((resp_headers, axum::body::Body::new(body)).into_response());
    }

    if wants_octet_stream {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| ApiError::NotFound(format!("open file: {e}")))?;

        if current_offset > 0 {
            file.seek(std::io::SeekFrom::Start(current_offset))
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("seek: {e}")))?;
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(mt) = &mtime {
            headers.insert(
                "X-File-MDate",
                mt.parse()
                    .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid mtime header")))?,
            );
        }
        headers.insert("X-File-Exists", HeaderValue::from_static("true"));

        let length_to_read = params
            .length
            .unwrap_or(file_size.saturating_sub(current_offset));
        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            const STREAM_CHUNK_SIZE: usize = 64 * 1024;
            let mut remaining = length_to_read;
            let mut buf = vec![0; STREAM_CHUNK_SIZE];

            loop {
                if remaining == 0 {
                    break;
                }
                let to_read = (buf.len() as u64).min(remaining) as usize;
                match file.read(&mut buf[..to_read]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        remaining -= n as u64;
                        if tx
                            .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..n]))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        let body = ReceiverBody { rx };
        return Ok((headers, axum::body::Body::new(body)).into_response());
    }

    let sha256 = if params.extensive {
        match hash_cache.get_or_compute(&path).await {
            Ok(h) => Some(h),
            Err(e) => {
                return Err(ApiError::Internal(anyhow::anyhow!("hash computation: {e}")))
            }
        }
    } else {
        None
    };

    let meta = FileInfo {
        name: filepath.to_owned(),
        is_dir: false,
        size: Some(file_size),
        mtime,
        sha256,
    };
    let val = serde_json::to_value(&meta)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("JSON serialization: {e}")))?;
    json_response(entry, req_sig, &val)
}

async fn put_file(
    Path((dir_id, filepath)): Path<(String, String)>,
    Query(params): Query<FileQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    put_file_inner(entry, &filepath, params, &headers, body).await
}

async fn put_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    headers: &HeaderMap,
    mut body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let fpath = resolve_canonical_write(entry, filepath)?;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let req_sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_default();

    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    // Check if it's our own streaming format
    if content_type == "application/vnd.filebridge.stream" {
        let (mut file, created) = open_for_write(&fpath, entry, params.offset.is_none()).await?;

        if let Some(off) = params.offset {
            file.seek(std::io::SeekFrom::Start(off))
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("seek: {e}")))?;
        }

        let expects_hmac = entry.token.is_some() && !req_sig.is_empty();
        let mut decoder = filebridge::stream::StreamDecoder::new();
        let mut aead = entry.token.as_ref().and_then(|t| {
            if req_sig.is_empty() {
                None
            } else {
                filebridge::stream::StreamAead::new(t, &req_sig).ok()
            }
        });

        // Track whether we ever received an HMAC frame if token is defined.
        let mut client_stop_received: Option<String> = None;
        let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);

        use http_body_util::BodyExt;

        while let Some(frame_res) = body.frame().await {
            let chunk = match frame_res {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        d
                    } else {
                        continue;
                    }
                }
                Err(e) => {
                    return Err(ApiError::Internal(anyhow::anyhow!("body read: {e}")))
                }
            };

            decoder.push(&chunk);

            while let Some(frame) = decoder
                .next_frame()
                .map_err(|e| ApiError::BadRequest(format!("stream decode: {e}")))?
            {
                match frame {
                    filebridge::stream::StreamFrame::Meta { .. } => {
                        // META frames handled at a higher level
                    }
                    filebridge::stream::StreamFrame::Data { payload } => {
                        if expects_hmac {
                            if let Some(ref mut a) = aead {
                                decrypt_buf.clear();
                                decrypt_buf.extend_from_slice(&payload);
                                if a.decrypt(&mut decrypt_buf).is_err() {
                                    return Err(ApiError::BadRequest(
                                        "chunk authenticated decryption failed".into(),
                                    ));
                                }
                                file.write_all(&decrypt_buf).await.map_err(|e| {
                                    ApiError::Internal(anyhow::anyhow!("write: {e}"))
                                })?;
                            } else {
                                return Err(ApiError::BadRequest(
                                    "expected AEAD but none configured".into(),
                                ));
                            }
                        } else {
                            file.write_all(&payload).await.map_err(|e| {
                                ApiError::Internal(anyhow::anyhow!("write: {e}"))
                            })?;
                        }
                    }
                    filebridge::stream::StreamFrame::Stop { signature } => {
                        client_stop_received = signature;
                    }
                }
            }
        }

        // Verify Stream Trailer if applicable
        if let Some(mut a) = aead {
            if let Some(client_stop) = client_stop_received {
                if a.verify_stop(&client_stop).is_err() {
                    return Err(ApiError::BadRequest(
                        "stream STOP AEAD signature mismatch".into(),
                    ));
                }
            } else {
                return Err(ApiError::BadRequest(
                    "token required but stream did not contain STOP frame".into(),
                ));
            }
        }

        let status = if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        #[cfg(unix)]
        if let Some(ref perms) = entry.file_permissions {
            apply_file_permissions(&fpath, perms).await?;
        }
        return Ok(status);
    }

    // ---------------------------------------------------------
    // Standard / direct file stream
    // ---------------------------------------------------------

    let offset = params.offset;

    let (mut file, created) = open_for_write(&fpath, entry, offset.is_none()).await?;

    if let Some(off) = offset {
        file.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("seek: {e}")))?;
    }

    use http_body_util::BodyExt;

    while let Some(frame_res) = body.frame().await {
        let chunk = match frame_res {
            Ok(f) => {
                if let Ok(d) = f.into_data() {
                    d
                } else {
                    continue; // Skip trailers etc.
                }
            }
            Err(e) => return Err(ApiError::Internal(anyhow::anyhow!("body read: {e}"))),
        };

        file.write_all(&chunk)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    }

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    #[cfg(unix)]
    if let Some(ref perms) = entry.file_permissions {
        apply_file_permissions(&fpath, perms).await?;
    }
    Ok(status)
}

#[cfg(unix)]
async fn apply_file_permissions(
    path: &std::path::Path,
    perms: &crate::config::FilePermissions,
) -> Result<(), ApiError> {
    if let Some(mode_bits) = perms.mode {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode_bits);
        tokio::fs::set_permissions(path, permissions).await.map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("chmod({:?}, {:o}): {e}", path, mode_bits))
        })?;
    }
    if perms.uid.is_some() || perms.gid.is_some() {
        let path = path.to_owned();
        let uid = perms.uid;
        let gid = perms.gid;
        tokio::task::spawn_blocking(move || {
            std::os::unix::fs::chown(&path, uid, gid).map_err(|e| {
                ApiError::Internal(anyhow::anyhow!(
                    "chown({:?}, {:?}, {:?}): {e}",
                    path,
                    uid,
                    gid
                ))
            })
        })
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("spawn_blocking join: {e}")))??;
    }
    Ok(())
}

async fn delete_file(
    Path((dir_id, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    delete_file_inner(entry, &filename, &state.hash_cache).await
}

async fn delete_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    hash_cache: &crate::cache::HashCache,
) -> Result<StatusCode, ApiError> {
    if !entry.allow_delete {
        return Err(ApiError::Forbidden("delete not allowed".into()));
    }

    let path = match resolve_canonical_path(entry, filepath) {
        Ok(p) => p,
        Err(ApiError::NotFound(_)) => return Ok(StatusCode::NO_CONTENT),
        Err(e) => return Err(e),
    };

    match tokio::fs::remove_file(&path).await {
        Ok(_) => {
            hash_cache.invalidate(&path);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => Err(ApiError::Internal(anyhow::anyhow!("remove file: {e}"))),
    }
}

// -------------------------------------------------------
// Encrypted body handlers: path in encrypted body, not URL
// -------------------------------------------------------

async fn encrypted_head(
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

    if !entry.allow_inspect {
        return Err(ApiError::Forbidden("inspect not allowed".into()));
    }

    resolve_canonical_path(entry, &envelope.path)?;
    Ok(StatusCode::OK)
}

async fn encrypted_put(
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

async fn encrypted_delete(
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

    delete_file_inner(entry, &envelope.path, &state.hash_cache).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::util::ServiceExt;

    use crate::config::{Config, LocationEntry};

    fn test_config(dir: &std::path::Path) -> Config {
        let mut locations = HashMap::new();
        locations.insert(
            "testloc".to_string(),
            LocationEntry {
                label: "testloc".to_string(),
                path: dir.to_path_buf(),
                allow_read: true,
                allow_create: true,
                allow_replace: true,
                allow_inspect: true,
                allow_delete: true,
                allow_recurse: false,
                token: None,
                #[cfg(unix)]
                file_permissions: None,
            },
        );
        Config { locations }
    }

    fn test_config_restricted(dir: &std::path::Path) -> Config {
        let mut locations = HashMap::new();
        locations.insert(
            "testloc".to_string(),
            LocationEntry {
                label: "testloc".to_string(),
                path: dir.to_path_buf(),
                allow_read: false,
                allow_create: false,
                allow_replace: false,
                allow_inspect: false,
                allow_delete: false,
                allow_recurse: false,
                token: None,
                #[cfg(unix)]
                file_permissions: None,
            },
        );
        Config { locations }
    }

    fn build_app(config: Config) -> axum::Router {
        super::routes(config)
    }

    #[tokio::test]
    async fn test_get_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_dir_unknown_location() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/nonexistent/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Unknown dir_id returns 200 with empty items (current behavior)
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/test.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_file_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/nope.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_file_forbidden_read() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config_restricted(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/test.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_head_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("HEAD")
            .uri("/api/v1/fs/testloc/test.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_head_file_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("HEAD")
            .uri("/api/v1/fs/testloc/nope.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_put_file_create() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/new.txt")
            .body(Body::from("file content"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(tmp.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn test_put_file_forbidden() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_restricted(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/new.txt")
            .body(Body::from("data"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/fs/testloc/test.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!tmp.path().join("test.txt").exists());
    }

    #[tokio::test]
    async fn test_delete_file_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/fs/testloc/nope.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Idempotent: deleting non-existent file returns 204
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_file_forbidden() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), b"hello").unwrap();
        let app = build_app(test_config_restricted(tmp.path()));

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/fs/testloc/test.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_put_read_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let content = b"roundtrip test content";

        // PUT
        let app = build_app(test_config(tmp.path()));
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/round.txt")
            .body(Body::from(content.as_slice()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // GET — read back and verify body
        let app = super::routes(config);
        let req = Request::builder()
            .uri("/api/v1/fs/testloc/round.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        // Response is JSON with file info, verify it's valid JSON
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json.get("name").is_some());
        assert_eq!(json["size"], content.len());
    }
}
