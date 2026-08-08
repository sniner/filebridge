mod envelope;
pub(crate) mod fs;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, head, post, put},
};
use bytes::Bytes;
use chrono::DateTime;
use hyper::body::{Body, Frame};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::config::LocationEntry;
use crate::error::ApiError;
use crate::models::FileInfo;

use self::envelope::{collect_envelope, decrypt_request_envelope};
use self::fs::{
    list_directory, open_for_write, rename_inner, resolve_canonical_path, resolve_canonical_write,
};

#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default)]
    pub extensive: bool,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub offset: Option<u64>,
    pub length: Option<u64>,
    #[serde(default)]
    pub extensive: bool,
}

/// Query parameters for a plaintext-mode rename: `POST /…/{filepath}?target=…`.
/// Token-mode clients send both paths in the encrypted envelope instead.
#[derive(Deserialize)]
pub struct RenameParams {
    pub target: String,
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
                .head(envelope::encrypted_head)
                .put(envelope::encrypted_put)
                .post(envelope::encrypted_rename)
                .delete(envelope::encrypted_delete)
                .options(options_dir),
        )
        .route("/api/v1/fs/{dir_id}/", get(get_dir).options(options_dir))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", get(get_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", head(has_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", put(put_file))
        .route("/api/v1/fs/{dir_id}/{*filepath:path}", post(rename_file))
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
    value: serde_json::Value,
) -> Result<Response, ApiError> {
    if let Some(token) = &entry.token {
        let json_bytes = serde_json::to_vec(&value)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("JSON serialization: {e}")))?;
        let encoded = filebridge::stream::encrypt_json(
            token,
            sig,
            &json_bytes,
            filebridge::stream::JsonDirection::Response,
        )
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("response encryption: {e}")))?;
        return Ok(Json(serde_json::json!({"message": encoded})).into_response());
    }
    Ok(Json(value).into_response())
}

// ---------------------------------------------------------------------------
// GET handlers
// ---------------------------------------------------------------------------

async fn get_dir(
    Path(dir_id): Path<String>,
    Query(params): Query<ListParams>,
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
        let token = entry.token.as_deref().ok_or(ApiError::BadRequest(
            "token required for encrypted request".into(),
        ))?;
        let body_bytes = collect_envelope(body).await?;
        let envelope = decrypt_request_envelope(token, sig, &body_bytes)?;
        tracing::info!("/{}", envelope.path);
        let params = FileQuery {
            offset: envelope.offset,
            length: envelope.length,
            extensive: envelope.extensive,
        };
        return get_file_inner(
            entry,
            &envelope.path,
            params,
            &headers,
            sig,
            &state.hash_cache,
        )
        .await;
    }

    tracing::info!("/");

    if !entry.allow_inspect {
        return json_response(
            entry,
            sig,
            serde_json::json!({"items": [], "detail": "Directory content hidden"}),
        );
    }

    match list_directory(
        &entry.path,
        entry.allow_recurse,
        params.extensive,
        &state.hash_cache,
    )
    .await
    {
        Ok(files) => json_response(entry, sig, serde_json::json!({"items": files})),
        Err(_) => json_response(
            entry,
            sig,
            serde_json::json!({"items": [], "detail": "Error reading directory"}),
        ),
    }
}

async fn options_dir(
    Path(dir_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    let sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let body = serde_json::json!({
        "location": entry.name,
        "permissions": {
            "read": entry.allow_read,
            "create": entry.allow_create,
            "replace": entry.allow_replace,
            "inspect": entry.allow_inspect,
            "delete": entry.allow_delete,
            "recurse": entry.allow_recurse,
            "mkdir": entry.allow_mkdir,
        }
    });

    json_response(entry, sig, body)
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

    tracing::info!("/{filepath}");
    get_file_inner(
        entry,
        &filepath,
        params,
        &headers,
        req_sig,
        &state.hash_cache,
    )
    .await
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

    tracing::trace!("candidate path = {:?}", entry.path.join(filepath));

    let path = resolve_canonical_path(entry, filepath)?;

    let metadata = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        // No path in the message — see the note in `resolve_canonical_path`.
        Err(_) => return Err(ApiError::NotFound("file not found".into())),
    };

    if metadata.is_dir() {
        if path != entry.path && !entry.allow_recurse {
            return Err(ApiError::Forbidden("recurse not allowed".into()));
        }
        if !entry.allow_inspect {
            return Err(ApiError::Forbidden("inspect not allowed".into()));
        }

        match list_directory(&path, entry.allow_recurse, params.extensive, hash_cache).await {
            Ok(files) => {
                return json_response(entry, req_sig, serde_json::json!({"items": files}));
            }
            Err(_) => {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "failed to list directory: {filepath}"
                )));
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
        return stream_file_response(
            &path,
            entry,
            req_sig,
            current_offset,
            params.length,
            file_size,
            &mtime,
        )
        .await;
    }

    // Token-protected locations must never send plaintext file content: the
    // Accept header is not covered by the request signature, so honouring an
    // octet-stream downgrade would let an on-path attacker read file contents.
    if wants_octet_stream {
        if entry.token.is_some() {
            return stream_file_response(
                &path,
                entry,
                req_sig,
                current_offset,
                params.length,
                file_size,
                &mtime,
            )
            .await;
        }
        return octet_stream_response(&path, current_offset, params.length, file_size, &mtime)
            .await;
    }

    let sha256 = if params.extensive {
        match hash_cache.get_or_compute(&path).await {
            Ok(h) => Some(h),
            Err(e) => return Err(ApiError::Internal(anyhow::anyhow!("hash computation: {e}"))),
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
    json_response(entry, req_sig, val)
}

// ---------------------------------------------------------------------------
// Streaming GET responses
// ---------------------------------------------------------------------------

async fn stream_file_response(
    path: &std::path::Path,
    entry: &LocationEntry,
    req_sig: &str,
    current_offset: u64,
    length: Option<u64>,
    file_size: u64,
    mtime: &Option<String>,
) -> Result<Response, ApiError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path)
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
    if let Some(mt) = mtime {
        resp_headers.insert(
            "X-File-MDate",
            mt.parse()
                .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid mtime header")))?,
        );
    }
    resp_headers.insert("X-File-Exists", HeaderValue::from_static("true"));

    let length_to_read = length.unwrap_or(file_size.saturating_sub(current_offset));

    // Calculate exact Content-Length for the stream frames.
    let encrypted = entry.token.is_some() && !req_sig.is_empty();
    let mac_overhead: u64 = if encrypted { 16 } else { 0 };
    let stop_size: u64 = if encrypted { 40 } else { 8 };
    let mut total_length = 0u64;
    let mut rem = length_to_read;
    while rem > 0 {
        let chunk_size = rem.min(64 * 1024);
        total_length += 8 + chunk_size + mac_overhead;
        rem -= chunk_size;
    }
    total_length += stop_size;
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
        let mut aead = token_opt.and_then(|t| {
            if req_sig_owned.is_empty() {
                None
            } else {
                filebridge::stream::StreamAead::new(&t, &req_sig_owned).ok()
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
    Ok((resp_headers, axum::body::Body::new(body)).into_response())
}

async fn octet_stream_response(
    path: &std::path::Path,
    current_offset: u64,
    length: Option<u64>,
    file_size: u64,
    mtime: &Option<String>,
) -> Result<Response, ApiError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path)
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
    if let Some(mt) = mtime {
        headers.insert(
            "X-File-MDate",
            mt.parse()
                .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid mtime header")))?,
        );
    }
    headers.insert("X-File-Exists", HeaderValue::from_static("true"));

    let length_to_read = length.unwrap_or(file_size.saturating_sub(current_offset));
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
    Ok((headers, axum::body::Body::new(body)).into_response())
}

// ---------------------------------------------------------------------------
// HEAD handler
// ---------------------------------------------------------------------------

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

    tracing::info!("/{filename}");
    resolve_canonical_path(entry, &filename)?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// PUT handler
// ---------------------------------------------------------------------------

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

    tracing::info!("/{filepath}");
    put_file_inner(entry, &filepath, params, &headers, body).await
}

async fn put_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    headers: &HeaderMap,
    mut body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let fpath = resolve_canonical_write(entry, filepath).await?;

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
                Err(e) => return Err(ApiError::Internal(anyhow::anyhow!("body read: {e}"))),
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
                            file.write_all(&payload)
                                .await
                                .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
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
            fs::apply_permissions(&fpath, perms).await?;
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
        fs::apply_permissions(&fpath, perms).await?;
    }
    Ok(status)
}

// ---------------------------------------------------------------------------
// DELETE handler
// ---------------------------------------------------------------------------

async fn delete_file(
    Path((dir_id, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    tracing::info!("/{filename}");
    fs::delete_file_inner(entry, &filename, &state.hash_cache).await
}

async fn rename_file(
    Path((dir_id, filepath)): Path<(String, String)>,
    Query(params): Query<RenameParams>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

    tracing::info!("/{filepath} -> /{}", params.target);
    rename_inner(entry, &filepath, &params.target, &state.hash_cache).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
                name: "testloc".to_string(),
                // Mirror Config::load, which canonicalizes location paths — the
                // raw tempdir is a symlink on macOS (/tmp) and non-UNC on Windows.
                path: dir.canonicalize().unwrap(),
                allow_read: true,
                allow_create: true,
                allow_replace: true,
                allow_inspect: true,
                allow_delete: true,
                allow_recurse: false,
                allow_mkdir: false,
                token: None,
                #[cfg(unix)]
                file_permissions: None,
                #[cfg(unix)]
                dir_permissions: None,
            },
        );
        Config { locations }
    }

    fn test_config_restricted(dir: &std::path::Path) -> Config {
        let mut locations = HashMap::new();
        locations.insert(
            "testloc".to_string(),
            LocationEntry {
                name: "testloc".to_string(),
                // Mirror Config::load, which canonicalizes location paths — the
                // raw tempdir is a symlink on macOS (/tmp) and non-UNC on Windows.
                path: dir.canonicalize().unwrap(),
                allow_read: false,
                allow_create: false,
                allow_replace: false,
                allow_inspect: false,
                allow_delete: false,
                allow_recurse: false,
                allow_mkdir: false,
                token: None,
                #[cfg(unix)]
                file_permissions: None,
                #[cfg(unix)]
                dir_permissions: None,
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
    async fn test_get_file_token_ignores_octet_stream_downgrade() {
        // Regression test for the plaintext-downgrade issue: the Accept header
        // is not covered by the request signature, so a token-protected
        // location must never answer with unencrypted file content.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use std::time::{SystemTime, UNIX_EPOCH};

        let tmp = tempfile::tempdir().unwrap();
        let plaintext = b"top secret content";
        std::fs::write(tmp.path().join("secret.txt"), plaintext).unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some("secret".to_string());
        let app = build_app(config);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "0011223344556677";
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"GET");
        mac.update(b"/api/v1/fs/testloc/secret.txt");
        let signature = hex::encode(mac.finalize().into_bytes());

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/secret.txt")
            .header("Accept", "application/octet-stream")
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            content_type.contains("application/vnd.filebridge.stream"),
            "expected encrypted stream, got {content_type:?}"
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !body
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_slice()),
            "plaintext file content leaked in response body"
        );
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

    fn test_config_with_flags(
        dir: &std::path::Path,
        allow_create: bool,
        allow_recurse: bool,
        allow_mkdir: bool,
    ) -> Config {
        let mut locations = HashMap::new();
        locations.insert(
            "testloc".to_string(),
            LocationEntry {
                name: "testloc".to_string(),
                // Mirror Config::load, which canonicalizes location paths — the
                // raw tempdir is a symlink on macOS (/tmp) and non-UNC on Windows.
                path: dir.canonicalize().unwrap(),
                allow_read: true,
                allow_create,
                allow_replace: true,
                allow_inspect: true,
                allow_delete: true,
                allow_recurse,
                allow_mkdir,
                token: None,
                #[cfg(unix)]
                file_permissions: None,
                #[cfg(unix)]
                dir_permissions: None,
            },
        );
        Config { locations }
    }

    #[tokio::test]
    async fn test_put_file_creates_missing_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), true, true, true));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/json/sub/file.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(tmp.path().join("json/sub").is_dir());
        assert!(tmp.path().join("json/sub/file.txt").is_file());
    }

    #[tokio::test]
    async fn test_put_file_mkdir_requires_create() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), false, true, true));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/sub/file.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!tmp.path().join("sub").exists());
    }

    #[tokio::test]
    async fn test_put_file_mkdir_requires_recurse() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), true, false, true));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/sub/file.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!tmp.path().join("sub").exists());
    }

    #[tokio::test]
    async fn test_put_file_mkdir_forbidden_without_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), true, true, false));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/sub/file.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(!tmp.path().join("sub").exists());
    }

    #[tokio::test]
    async fn test_options_returns_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), true, true, true));

        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/fs/testloc")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["location"], "testloc");
        let perms = &json["permissions"];
        assert_eq!(perms["read"], true);
        assert_eq!(perms["create"], true);
        assert_eq!(perms["replace"], true);
        assert_eq!(perms["inspect"], true);
        assert_eq!(perms["delete"], true);
        assert_eq!(perms["recurse"], true);
        assert_eq!(perms["mkdir"], true);
    }

    #[tokio::test]
    async fn test_options_restricted_location() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_restricted(tmp.path()));

        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/fs/testloc")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let perms = &json["permissions"];
        assert_eq!(perms["read"], false);
        assert_eq!(perms["create"], false);
        assert_eq!(perms["mkdir"], false);
    }

    #[tokio::test]
    async fn test_options_unknown_location() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/fs/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_put_file_rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config_with_flags(tmp.path(), true, true, true));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/..%2Fevil.txt")
            .body(Body::from("payload"))
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

    // -----------------------------------------------------------------------
    // Rename
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rename_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=new.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!tmp.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(tmp.path().join("new.txt")).unwrap(),
            b"hello".to_vec()
        );
    }

    #[tokio::test]
    async fn test_rename_file_source_not_found() {
        // Unlike DELETE, rename is not idempotent — a missing source is an error,
        // not a silent success.
        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/nope.txt?target=new.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rename_missing_target_param() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_rejects_target_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=..%2Fevil.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_requires_create_permission() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"hello").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().allow_create = false;
        let app = build_app(config);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=new.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_requires_delete_permission() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"hello").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().allow_delete = false;
        let app = build_app(config);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=new.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_over_existing_target_requires_replace() {
        // Without this guard a create-only location could overwrite existing
        // files through rename — precisely what open_for_write refuses on PUT.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"new content").unwrap();
        std::fs::write(tmp.path().join("victim.txt"), b"do not clobber").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().allow_replace = false;
        let app = build_app(config);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=victim.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            std::fs::read(tmp.path().join("victim.txt")).unwrap(),
            b"do not clobber".to_vec()
        );
    }

    #[tokio::test]
    async fn test_rename_over_existing_target_with_replace() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"new content").unwrap();
        std::fs::write(tmp.path().join("target.txt"), b"old content").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/old.txt?target=target.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            std::fs::read(tmp.path().join("target.txt")).unwrap(),
            b"new content".to_vec()
        );
    }

    #[tokio::test]
    async fn test_rename_directory_rejected() {
        // Windows' MOVEFILE_REPLACE_EXISTING does not cover directories, so
        // allowing them would make the endpoint platform-dependent.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/subdir?target=renamed")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(tmp.path().join("subdir").is_dir());
    }

    #[tokio::test]
    async fn test_rename_invalidates_hash_cache_for_target() {
        use sha2::{Digest, Sha256};

        // The cache key is (path, mtime, size). This builds the exact collision
        // that key cannot see through: the renamed-in file has the same size and
        // the same mtime as the file previously cached under the target path.
        // Without an explicit invalidation the stale hash would survive.
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.txt");
        let b = tmp.path().join("b.txt");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"two").unwrap();
        let mtime = filetime::FileTime::from_system_time(
            std::fs::metadata(&a).unwrap().modified().unwrap(),
        );
        filetime::set_file_mtime(&b, mtime).unwrap();

        // A cloned Router shares the AppState, and with it the hash cache —
        // building a second app would hand the test a fresh, empty cache.
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/a.txt?extensive=true")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let hash_before = json["sha256"].as_str().unwrap().to_string();
        assert_eq!(hash_before, hex::encode(Sha256::digest(b"one")));

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc/b.txt?target=a.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/a.txt?extensive=true")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let hash_after = json["sha256"].as_str().unwrap();

        assert_eq!(
            hash_after,
            hex::encode(Sha256::digest(b"two")),
            "stale hash served for the renamed-in file"
        );
    }

    /// Builds the HMAC signature for a token-mode request against `uri`.
    fn sign(token: &str, method: &str, uri: &str, timestamp: &str, nonce: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes()).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(method.as_bytes());
        mac.update(uri.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn now_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[tokio::test]
    async fn test_rename_token_mode_via_envelope() {
        // Token-mode clients keep both paths out of the URL, so they arrive in
        // the encrypted envelope instead.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"payload").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some("secret".to_string());
        let app = build_app(config);

        let timestamp = now_timestamp();
        let nonce = "0011223344556677";
        let signature = sign("secret", "POST", "/api/v1/fs/testloc", &timestamp, nonce);

        let envelope = serde_json::json!({"path": "old.txt", "target": "new.txt"});
        let body = filebridge::stream::encrypt_json(
            "secret",
            &signature,
            &serde_json::to_vec(&envelope).unwrap(),
            filebridge::stream::JsonDirection::Request,
        )
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc")
            .header("Content-Type", "application/vnd.filebridge.request")
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!tmp.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(tmp.path().join("new.txt")).unwrap(),
            b"payload".to_vec()
        );
    }

    #[tokio::test]
    async fn test_error_body_does_not_leak_path_in_token_mode() {
        // Sibling of test_get_file_token_ignores_octet_stream_downgrade: token mode
        // carries the path in an encrypted envelope so it stays off the wire, and an
        // error response must not hand it straight back. Error bodies are rendered
        // by `impl IntoResponse for ApiError` and are *not* encrypted, so the only
        // thing keeping the path out of them is that it is never formatted in.
        const SECRET_PATH: &str = "kunden/geheim/DE20-HU70-schneideliste.LNK";

        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some("secret".to_string());
        let app = build_app(config);

        let timestamp = now_timestamp();
        let nonce = "aabbccddeeff0011";
        let signature = sign("secret", "GET", "/api/v1/fs/testloc", &timestamp, nonce);

        let envelope = serde_json::json!({"path": SECRET_PATH});
        let body = filebridge::stream::encrypt_json(
            "secret",
            &signature,
            &serde_json::to_vec(&envelope).unwrap(),
            filebridge::stream::JsonDirection::Request,
        )
        .unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/fs/testloc")
            .header("Content-Type", "application/vnd.filebridge.request")
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !body
                .windows(SECRET_PATH.len())
                .any(|w| w == SECRET_PATH.as_bytes()),
            "path leaked in cleartext error body: {:?}",
            String::from_utf8_lossy(&body)
        );
        // Not even a fragment of it — a partial path is a leak too.
        assert!(
            !body
                .windows("schneideliste".len())
                .any(|w| w == b"schneideliste"),
            "path fragment leaked in cleartext error body: {:?}",
            String::from_utf8_lossy(&body)
        );
    }

    #[tokio::test]
    async fn test_rename_error_body_does_not_leak_path() {
        // Same property for the rename source path, which reaches the client
        // through a different handler.
        const SECRET_PATH: &str = "kunden/geheim/auftrag-4711.LNK";

        let tmp = tempfile::tempdir().unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/fs/testloc/{SECRET_PATH}?target=anderswo.LNK"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !body
                .windows("auftrag-4711".len())
                .any(|w| w == b"auftrag-4711"),
            "path leaked in cleartext error body: {:?}",
            String::from_utf8_lossy(&body)
        );
    }

    #[tokio::test]
    async fn test_rename_token_mode_requires_target() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"payload").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some("secret".to_string());
        let app = build_app(config);

        let timestamp = now_timestamp();
        let nonce = "8899aabbccddeeff";
        let signature = sign("secret", "POST", "/api/v1/fs/testloc", &timestamp, nonce);

        // A plain envelope without `target` — what a DELETE would send.
        let envelope = serde_json::json!({"path": "old.txt"});
        let body = filebridge::stream::encrypt_json(
            "secret",
            &signature,
            &serde_json::to_vec(&envelope).unwrap(),
            filebridge::stream::JsonDirection::Request,
        )
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/fs/testloc")
            .header("Content-Type", "application/vnd.filebridge.request")
            .header("X-Signature", signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(tmp.path().join("old.txt").exists());
    }
}
