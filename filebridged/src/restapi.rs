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
async fn collect_envelope(body: axum::body::Body) -> Result<bytes::Bytes, StatusCode> {
    use http_body_util::BodyExt;
    let mut total = 0usize;
    let mut buf = bytes::BytesMut::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            total += data.len();
            if total > MAX_ENVELOPE_SIZE {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
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
) -> Result<PathBuf, StatusCode> {
    let full = entry.path.join(filepath);
    let parent = full.parent().ok_or(StatusCode::FORBIDDEN)?;
    let canon_parent = parent.canonicalize().map_err(|_| StatusCode::FORBIDDEN)?;
    if !canon_parent.starts_with(&entry.path)
        || (!entry.allow_recurse && canon_parent != entry.path)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let file_name = full.file_name().ok_or(StatusCode::FORBIDDEN)?;
    Ok(canon_parent.join(file_name))
}

/// Open a file for writing atomically, respecting allow_create/allow_replace permissions.
/// Returns the file handle and whether the file was newly created.
async fn open_for_write(
    fpath: &std::path::Path,
    entry: &LocationEntry,
    truncate: bool,
) -> Result<(tokio::fs::File, bool), StatusCode> {
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
                    return Err(StatusCode::FORBIDDEN);
                }
                let f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(truncate)
                    .open(fpath)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                return Ok((f, false));
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StatusCode::FORBIDDEN),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn resolve_canonical_path(entry: &LocationEntry, filepath: &str) -> Result<PathBuf, StatusCode> {
    let full = entry.path.join(filepath);
    let canon = full.canonicalize().map_err(|_| StatusCode::NOT_FOUND)?;
    if !canon.starts_with(&entry.path)
        || (!entry.allow_recurse
            && canon != entry.path
            && canon.parent() != Some(entry.path.as_path()))
    {
        return Err(StatusCode::FORBIDDEN);
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
) -> Result<RequestEnvelope, StatusCode> {
    let body_str = std::str::from_utf8(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let json_bytes = filebridge::stream::decrypt_json_response(token, sig, body_str)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    serde_json::from_slice(&json_bytes).map_err(|_| StatusCode::BAD_REQUEST)
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
) -> Result<Response, StatusCode> {
    if let Some(token) = &entry.token {
        let json_bytes =
            serde_json::to_vec(value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let encoded = filebridge::stream::encrypt_json_response(token, sig, &json_bytes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
) -> Result<Response, StatusCode> {
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
        let token = entry.token.as_deref().ok_or(StatusCode::BAD_REQUEST)?;
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
            let is_dir = ft.is_dir();
            if !is_dir && !ft.is_file() {
                continue;
            }
            if is_dir && !allow_recurse {
                continue;
            }

            if let Some(name) = entry.file_name().to_str() {
                let (size, mdate) = if is_dir {
                    (None, None)
                } else {
                    match entry.metadata() {
                        Ok(meta) => {
                            let size = Some(meta.len());
                            let mdate = meta
                                .modified()
                                .ok()
                                .and_then(|mt| mt.duration_since(SystemTime::UNIX_EPOCH).ok())
                                .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
                                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                            (size, mdate)
                        }
                        Err(_) => (None, None),
                    }
                };
                files.push(FileInfo {
                    name: name.to_string(),
                    is_dir,
                    size,
                    mdate,
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
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };

    if !entry.allow_inspect {
        return StatusCode::FORBIDDEN;
    }

    let _path = match resolve_canonical_path(entry, &filename) {
        Ok(p) => p,
        Err(StatusCode::NOT_FOUND) => return StatusCode::NOT_FOUND,
        Err(StatusCode::FORBIDDEN) => return StatusCode::FORBIDDEN,
        _ => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    StatusCode::OK
}

async fn get_file(
    Path((dir_id, filepath)): Path<(String, String)>,
    Query(params): Query<FileQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(StatusCode::NOT_FOUND);
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
) -> Result<Response, StatusCode> {
    if !entry.allow_read {
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::debug!("candidate path = {:?}", entry.path.join(filepath));

    let path = resolve_canonical_path(entry, filepath)?;

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    if metadata.is_dir() {
        if path != entry.path && !entry.allow_recurse {
            return Err(StatusCode::FORBIDDEN);
        }
        if !entry.allow_inspect {
            return Err(StatusCode::FORBIDDEN);
        }

        match list_directory(&path, entry.allow_recurse) {
            Ok(files) => {
                return json_response(entry, req_sig, &serde_json::json!({"items": files}));
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
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
            .map_err(|_| StatusCode::NOT_FOUND)?;

        if current_offset > 0 {
            file.seek(std::io::SeekFrom::Start(current_offset))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.filebridge.stream"),
        );
        if let Some(mt) = &mtime {
            resp_headers.insert("X-File-MDate", mt.parse().expect("valid mtime header"));
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
            total_length.to_string().parse().expect("valid u64 header"),
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
            .map_err(|_| StatusCode::NOT_FOUND)?;

        if current_offset > 0 {
            file.seek(std::io::SeekFrom::Start(current_offset))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(mt) = &mtime {
            headers.insert("X-File-MDate", mt.parse().expect("valid mtime header"));
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
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        None
    };

    let meta = FileInfo {
        name: filepath.to_owned(),
        is_dir: false,
        size: Some(file_size),
        mdate: mtime,
        sha256,
    };
    let val = serde_json::to_value(&meta).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    json_response(entry, req_sig, &val)
}

async fn put_file(
    Path((dir_id, filepath)): Path<(String, String)>,
    Query(params): Query<FileQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: axum::body::Body,
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };

    put_file_inner(entry, &filepath, params, &headers, body).await
}

async fn put_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    headers: &HeaderMap,
    mut body: axum::body::Body,
) -> StatusCode {
    let fpath = match resolve_canonical_write(entry, filepath) {
        Ok(p) => p,
        Err(code) => return code,
    };

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
        let (mut file, created) =
            match open_for_write(&fpath, entry, params.offset.is_none()).await {
                Ok(r) => r,
                Err(code) => return code,
            };

        if let Some(off) = params.offset
            && file.seek(std::io::SeekFrom::Start(off)).await.is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR;
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
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
            };

            decoder.push(&chunk);

            while let Some(frame) = match decoder.next_frame() {
                Ok(f) => f,
                Err(_) => return StatusCode::BAD_REQUEST,
            } {
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
                                    tracing::warn!("Chunk Authenticated Decryption Failed");
                                    return StatusCode::BAD_REQUEST;
                                }
                                if file.write_all(&decrypt_buf).await.is_err() {
                                    return StatusCode::INTERNAL_SERVER_ERROR;
                                }
                            } else {
                                return StatusCode::BAD_REQUEST;
                            }
                        } else if file.write_all(&payload).await.is_err() {
                            return StatusCode::INTERNAL_SERVER_ERROR;
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
                    tracing::warn!("Stream STOP AEAD signature mismatch");
                    return StatusCode::BAD_REQUEST;
                }
            } else {
                tracing::warn!("Token is required but stream did not contain STOP frame");
                return StatusCode::BAD_REQUEST;
            }
        }

        let status = if created { StatusCode::CREATED } else { StatusCode::OK };
        #[cfg(unix)]
        if let Some(ref perms) = entry.file_permissions
            && let Err(code) = apply_file_permissions(&fpath, perms).await
        {
            return code;
        }
        return status;
    }

    // ---------------------------------------------------------
    // Standard / direct file stream
    // ---------------------------------------------------------

    let offset = params.offset;

    let (mut file, created) =
        match open_for_write(&fpath, entry, offset.is_none()).await {
            Ok(r) => r,
            Err(code) => return code,
        };

    if let Some(off) = offset
        && file.seek(std::io::SeekFrom::Start(off)).await.is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
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
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
        };

        if file.write_all(&chunk).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    #[cfg(unix)]
    if let Some(ref perms) = entry.file_permissions
        && let Err(code) = apply_file_permissions(&fpath, perms).await
    {
        return code;
    }
    status
}

#[cfg(unix)]
async fn apply_file_permissions(
    path: &std::path::Path,
    perms: &crate::config::FilePermissions,
) -> Result<(), StatusCode> {
    if let Some(mode_bits) = perms.mode {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode_bits);
        tokio::fs::set_permissions(path, permissions).await.map_err(|e| {
            tracing::warn!("chmod({:?}, {:o}) failed: {}", path, mode_bits, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }
    if perms.uid.is_some() || perms.gid.is_some() {
        let path = path.to_owned();
        let uid = perms.uid;
        let gid = perms.gid;
        tokio::task::spawn_blocking(move || {
            std::os::unix::fs::chown(&path, uid, gid).map_err(|e| {
                tracing::warn!("chown({:?}, {:?}, {:?}) failed: {}", path, uid, gid, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;
    }
    Ok(())
}

async fn delete_file(
    Path((dir_id, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };

    delete_file_inner(entry, &filename).await
}

async fn delete_file_inner(entry: &LocationEntry, filepath: &str) -> StatusCode {
    if !entry.allow_delete {
        return StatusCode::FORBIDDEN;
    }

    let path = match resolve_canonical_path(entry, filepath) {
        Ok(p) => p,
        Err(StatusCode::NOT_FOUND) => return StatusCode::NO_CONTENT,
        Err(StatusCode::FORBIDDEN) => return StatusCode::FORBIDDEN,
        _ => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    match tokio::fs::remove_file(&path).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };
    let Some(token) = &entry.token else {
        return StatusCode::BAD_REQUEST;
    };
    let sig = match headers.get("X-Signature").and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED,
    };

    let body_bytes = match collect_envelope(body).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let envelope = match decrypt_request_envelope(token, sig, &body_bytes) {
        Ok(e) => e,
        Err(code) => return code,
    };

    if !entry.allow_inspect {
        return StatusCode::FORBIDDEN;
    }

    match resolve_canonical_path(entry, &envelope.path) {
        Ok(_) => StatusCode::OK,
        Err(StatusCode::NOT_FOUND) => StatusCode::NOT_FOUND,
        Err(StatusCode::FORBIDDEN) => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn encrypted_put(
    Path(dir_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
    mut body: axum::body::Body,
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };
    let Some(token) = &entry.token else {
        return StatusCode::BAD_REQUEST;
    };
    let sig = match headers.get("X-Signature").and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED,
    };

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if content_type != "application/vnd.filebridge.stream" {
        return StatusCode::BAD_REQUEST;
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
                        Ok(Some(_)) => return StatusCode::BAD_REQUEST, // Expected META first
                        Ok(None) => continue,                          // Need more data
                        Err(_) => return StatusCode::BAD_REQUEST,
                    }
                }
            }
            Some(Err(_)) => return StatusCode::BAD_REQUEST,
            None => return StatusCode::BAD_REQUEST, // EOF before META
        }
    }

    // Decrypt the META payload to get the request envelope
    let meta_str = match std::str::from_utf8(&meta_payload) {
        Ok(s) => s,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let json_bytes = match filebridge::stream::decrypt_json_response(token, sig, meta_str) {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let envelope: RequestEnvelope = match serde_json::from_slice(&json_bytes) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

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
) -> StatusCode {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return StatusCode::NOT_FOUND;
    };
    let Some(token) = &entry.token else {
        return StatusCode::BAD_REQUEST;
    };
    let sig = match headers.get("X-Signature").and_then(|h| h.to_str().ok()) {
        Some(s) => s,
        None => return StatusCode::UNAUTHORIZED,
    };

    let body_bytes = match collect_envelope(body).await {
        Ok(b) => b,
        Err(code) => return code,
    };
    let envelope = match decrypt_request_envelope(token, sig, &body_bytes) {
        Ok(e) => e,
        Err(code) => return code,
    };

    delete_file_inner(entry, &envelope.path).await
}
