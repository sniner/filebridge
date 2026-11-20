#[cfg(test)]
mod client_tests;
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
    WriteTarget, list_directory, rename_inner, resolve_canonical_path, resolve_canonical_write,
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
        // `route_layer`: the middleware reads the location name from the path
        // parameters of the matched route.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_middleware,
        ))
        .with_state(state)
}

/// What a GET for a file is answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileResponse {
    /// The metadata of the file as JSON.
    Metadata,
    /// The content in stream frames, encrypted for a location with a token.
    Stream,
    /// The content as it is.
    OctetStream,
}

impl FileResponse {
    /// The response a request to a location without a token asks for.
    fn from_accept(headers: &HeaderMap) -> Self {
        let accept = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let accepts = |media_type: &str| accept.split(',').any(|p| p.trim() == media_type);
        if accepts("application/vnd.filebridge.stream") {
            Self::Stream
        } else if accepts("application/octet-stream") {
            Self::OctetStream
        } else {
            Self::Metadata
        }
    }
}

/// File content of a location with a token is only read and written under
/// the keys of a signed request. `auth_middleware` lets no other request
/// through; this keeps a mistake there from turning into plain-text access.
fn require_signature(entry: &LocationEntry, signature: &str) -> Result<(), ApiError> {
    if entry.token.is_some() && signature.is_empty() {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "location {:?} has a token, but the request has no signature",
            entry.name
        )));
    }
    Ok(())
}

/// A JSON result. For a location with a token, `auth_middleware` encrypts it
/// together with the status; no handler encrypts a response itself, except for
/// file streams.
fn json_response(value: serde_json::Value) -> Result<Response, ApiError> {
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

    // A location with a token takes everything about the request from the
    // encrypted body: the path, and whether metadata or content is wanted.
    // Content-Type and Accept are not signed. If they decided, changing them
    // in transit would turn a request for one path into a listing of the root,
    // or a request for metadata into a download whose size shows that the path
    // is a file and how large it is.
    if let Some(token) = entry.token.as_deref() {
        let body_bytes = collect_envelope(body).await?;
        let envelope = decrypt_request_envelope(token, sig, &body_bytes)?;
        tracing::info!("/{}", envelope.path);
        let params = FileQuery {
            offset: envelope.offset,
            length: envelope.length,
            extensive: envelope.extensive,
        };
        let wanted = if envelope.content {
            FileResponse::Stream
        } else {
            FileResponse::Metadata
        };
        return get_file_inner(
            entry,
            &envelope.path,
            params,
            wanted,
            sig,
            &state.hash_cache,
        )
        .await;
    }
    if content_type == "application/vnd.filebridge.request" {
        return Err(ApiError::BadRequest(
            "token required for encrypted request".into(),
        ));
    }

    tracing::info!("/");

    if !entry.allow_inspect {
        return json_response(
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
        Ok(files) => json_response(serde_json::json!({"items": files})),
        Err(_) => {
            json_response(serde_json::json!({"items": [], "detail": "Error reading directory"}))
        }
    }
}

async fn options_dir(
    Path(dir_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let Some(entry) = state.config.get_location(&dir_id) else {
        return Err(ApiError::NotFound(format!("unknown location: {dir_id}")));
    };

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

    json_response(body)
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
        FileResponse::from_accept(&headers),
        req_sig,
        &state.hash_cache,
    )
    .await
}

async fn get_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    wanted: FileResponse,
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
                return json_response(serde_json::json!({"items": files}));
            }
            Err(_) => {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "failed to list directory: {filepath}"
                )));
            }
        }
    }

    let file_size = metadata.len();
    let current_offset = params.offset.unwrap_or(0);

    let mtime = metadata
        .modified()
        .ok()
        .and_then(|mtime| mtime.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

    match wanted {
        FileResponse::Metadata => {}
        FileResponse::OctetStream if entry.token.is_none() => {
            return octet_stream_response(&path, current_offset, params.length, file_size, &mtime)
                .await;
        }
        // A location with a token sends file content in encrypted frames only.
        FileResponse::Stream | FileResponse::OctetStream => {
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
    json_response(val)
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

    require_signature(entry, req_sig)?;
    let encrypted = entry.token.is_some();

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.filebridge.stream"),
    );
    // Headers are not encrypted, so an encrypted stream carries no metadata
    // of the file in them.
    if !encrypted {
        if let Some(mt) = mtime {
            resp_headers.insert(
                "X-File-MDate",
                mt.parse()
                    .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid mtime header")))?,
            );
        }
        resp_headers.insert("X-File-Exists", HeaderValue::from_static("true"));
    }

    // Never more than the file has left: the frames are announced in
    // Content-Length before the first byte is read.
    let available = file_size.saturating_sub(current_offset);
    let length_to_read = length.map_or(available, |l| l.min(available));

    // Calculate exact Content-Length for the stream frames.
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

    // Before the response starts: without its cipher, a location with a token
    // sends nothing at all.
    let mut aead = match entry.token.as_deref() {
        Some(token) => Some(
            filebridge::stream::StreamAead::new(token, req_sig)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("stream key: {e}")))?,
        ),
        None => None,
    };

    let (tx, rx) = mpsc::channel(128);

    tokio::spawn(async move {
        const STREAM_CHUNK_SIZE: usize = 64 * 1024;
        let encryption_failed =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed");
        let mut remaining = length_to_read;
        let mut buf = vec![0; STREAM_CHUNK_SIZE];
        let mut chunk: Vec<u8> = Vec::with_capacity(STREAM_CHUNK_SIZE + 16 + 1);

        loop {
            if remaining == 0 {
                let stop = match aead.as_mut().map(filebridge::stream::StreamAead::finalize) {
                    None => Ok(filebridge::stream::encode_stop(None)),
                    Some(Ok(tag)) => Ok(filebridge::stream::encode_stop(Some(&tag))),
                    Some(Err(_)) => Err(encryption_failed()),
                };
                // The client is gone if this fails, and nobody is left to tell.
                drop(
                    tx.send(stop.map(|frame| Frame::data(Bytes::from(frame))))
                        .await,
                );
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
                        let _ = tx.send(Err(encryption_failed())).await;
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
    let mut response = (resp_headers, axum::body::Body::new(body)).into_response();
    if encrypted {
        response
            .extensions_mut()
            .insert(crate::auth::EncryptedStream);
    }
    Ok(response)
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

/// How the body of an upload carries the content of the file.
enum UploadBody {
    /// The content as it is.
    Raw,
    /// Stream frames with the content in plain text.
    Frames,
    /// Stream frames, encrypted and authenticated under the keys of the request.
    Encrypted(filebridge::stream::StreamAead),
}

async fn put_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    params: FileQuery,
    headers: &HeaderMap,
    body: axum::body::Body,
) -> Result<StatusCode, ApiError> {
    let req_sig = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    require_signature(entry, req_sig)?;

    let fpath = resolve_canonical_write(entry, filepath).await?;

    let framed = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|t| t == "application/vnd.filebridge.stream");
    let upload = match (entry.token.as_deref(), framed) {
        (Some(token), true) => UploadBody::Encrypted(
            filebridge::stream::StreamAead::new(token, req_sig)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("stream key: {e}")))?,
        ),
        // A location with a token takes file content in encrypted frames only.
        (Some(_), false) => {
            return Err(ApiError::BadRequest(
                "expected vnd.filebridge.stream content type".into(),
            ));
        }
        (None, true) => UploadBody::Frames,
        (None, false) => UploadBody::Raw,
    };

    let mut target = WriteTarget::open(&fpath, entry, params.offset).await?;
    receive_upload(target.file_mut(), body, upload).await?;
    target.commit(entry).await
}

/// Writes the content of an upload to `file`.
///
/// An error means the upload is incomplete or not authentic. The caller then
/// drops the [`WriteTarget`] instead of committing it.
async fn receive_upload(
    file: &mut tokio::fs::File,
    mut body: axum::body::Body,
    upload: UploadBody,
) -> Result<(), ApiError> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;

    let read_err = |e| ApiError::Internal(anyhow::anyhow!("body read: {e}"));
    let write_err = |e| ApiError::Internal(anyhow::anyhow!("write: {e}"));

    let mut aead = match upload {
        UploadBody::Raw => {
            while let Some(frame) = body.frame().await {
                // Anything but data is a trailer.
                if let Ok(data) = frame.map_err(read_err)?.into_data() {
                    file.write_all(&data).await.map_err(write_err)?;
                }
            }
            return Ok(());
        }
        UploadBody::Frames => None,
        UploadBody::Encrypted(aead) => Some(aead),
    };

    let mut decoder = filebridge::stream::StreamDecoder::new();
    let mut stop: Option<String> = None;
    let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);

    while let Some(frame) = body.frame().await {
        let Ok(chunk) = frame.map_err(read_err)?.into_data() else {
            continue;
        };
        decoder.push(&chunk);

        while let Some(frame) = decoder
            .next_frame()
            .map_err(|e| ApiError::BadRequest(format!("stream decode: {e}")))?
        {
            match frame {
                // The request envelope, which `encrypted_put` has read.
                filebridge::stream::StreamFrame::Meta { .. } => {}
                filebridge::stream::StreamFrame::Data { payload } => match aead.as_mut() {
                    Some(aead) => {
                        decrypt_buf.clear();
                        decrypt_buf.extend_from_slice(&payload);
                        aead.decrypt(&mut decrypt_buf).map_err(|_| {
                            ApiError::BadRequest("chunk authenticated decryption failed".into())
                        })?;
                        file.write_all(&decrypt_buf).await.map_err(write_err)?;
                    }
                    None => file.write_all(&payload).await.map_err(write_err)?,
                },
                filebridge::stream::StreamFrame::Stop { signature } => stop = signature,
            }
        }
    }

    // Every DATA frame is authentic on its own. Only the STOP frame shows that
    // none is missing at the end.
    if let Some(mut aead) = aead {
        let Some(stop) = stop else {
            return Err(ApiError::BadRequest(
                "token required but stream did not contain STOP frame".into(),
            ));
        };
        aead.verify_stop(&stop)
            .map_err(|_| ApiError::BadRequest("stream STOP AEAD signature mismatch".into()))?;
    }
    Ok(())
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
                fsync: false,
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
                fsync: false,
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
        let tmp = tempfile::tempdir().unwrap();
        let plaintext = b"top secret content";
        std::fs::write(tmp.path().join("secret.txt"), plaintext).unwrap();
        let app = token_app(tmp.path());

        let (mut req, _) = token_request(
            "GET",
            &serde_json::json!({"path": "secret.txt", "content": true}),
        );
        req.headers_mut()
            .insert("Accept", "application/octet-stream".parse().unwrap());
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
        // Headers are readable on the wire, so they say nothing about the file.
        assert!(resp.headers().get("X-File-MDate").is_none());
        assert!(resp.headers().get("X-File-Exists").is_none());

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
                fsync: false,
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

    const TOKEN: &str = "secret";
    const TOKEN_URI: &str = "/api/v1/fs/testloc";

    /// The test location, protected by [`TOKEN`].
    fn token_app(dir: &std::path::Path) -> axum::Router {
        let mut config = test_config(dir);
        config.locations.get_mut("testloc").unwrap().token = Some(TOKEN.to_string());
        build_app(config)
    }

    /// Signature and headers of a token-mode request to [`TOKEN_URI`], with a
    /// nonce of its own.
    fn signed(method: &str) -> (axum::http::request::Builder, String) {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static NONCE: AtomicU64 = AtomicU64::new(1);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = format!("{:016x}", NONCE.fetch_add(1, Ordering::Relaxed));
        let signature = hex::encode(
            filebridge::stream::request_signature(TOKEN, &timestamp, &nonce, method, TOKEN_URI)
                .unwrap(),
        );
        let builder = Request::builder()
            .method(method)
            .uri(TOKEN_URI)
            .header("X-Signature", &signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce);
        (builder, signature)
    }

    fn encrypt_envelope(signature: &str, envelope: &serde_json::Value) -> String {
        filebridge::stream::encrypt_json(
            TOKEN,
            signature,
            &serde_json::to_vec(envelope).unwrap(),
            filebridge::stream::JsonDirection::Request,
        )
        .unwrap()
    }

    /// A token-mode request whose body is the encrypted `envelope`. Returns the
    /// request and its signature, which the response is decrypted with.
    fn token_request(method: &str, envelope: &serde_json::Value) -> (Request<Body>, String) {
        let (builder, signature) = signed(method);
        let req = builder
            .header("Content-Type", "application/vnd.filebridge.request")
            .body(Body::from(encrypt_envelope(&signature, envelope)))
            .unwrap();
        (req, signature)
    }

    /// A token-mode upload of `content` to `path`.
    fn token_put(path: &str, content: &[u8]) -> (Request<Body>, String) {
        let (builder, signature) = signed("PUT");
        let envelope = encrypt_envelope(&signature, &serde_json::json!({"path": path}));
        let mut aead = filebridge::stream::StreamAead::new(TOKEN, &signature).unwrap();
        let mut chunk = content.to_vec();
        aead.encrypt(&mut chunk).unwrap();

        let mut body = filebridge::stream::encode_meta(envelope.as_bytes());
        body.extend(filebridge::stream::encode_data(&chunk));
        body.extend(filebridge::stream::encode_stop(Some(
            &aead.finalize().unwrap(),
        )));
        let req = builder
            .header("Content-Type", "application/vnd.filebridge.stream")
            .body(Body::from(body))
            .unwrap();
        (req, signature)
    }

    /// Sends `req` and decrypts the response, which must be an encrypted reply:
    /// status line 200, JSON, and nothing readable about the outcome.
    async fn token_reply(
        app: axum::Router,
        (req, signature): (Request<Body>, String),
    ) -> filebridge::stream::Reply {
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        filebridge::stream::open_reply(TOKEN, &signature, &body).unwrap()
    }

    #[tokio::test]
    async fn test_rename_token_mode_via_envelope() {
        // Token-mode clients keep both paths out of the URL, so they arrive in
        // the encrypted envelope instead.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"payload").unwrap();

        let reply = token_reply(
            token_app(tmp.path()),
            token_request(
                "POST",
                &serde_json::json!({"path": "old.txt", "target": "new.txt"}),
            ),
        )
        .await;
        assert_eq!(reply.status, 204);
        assert!(!tmp.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(tmp.path().join("new.txt")).unwrap(),
            b"payload".to_vec()
        );
    }

    #[tokio::test]
    async fn test_token_mode_error_is_encrypted() {
        // The error of a token-mode request is as much a statement about the
        // file as its content is: status and message are in the encrypted
        // body, and the response is indistinguishable from a success by its
        // status line and headers.
        const SECRET_PATH: &str = "archive/ledger-2031.txt";

        let tmp = tempfile::tempdir().unwrap();
        let app = token_app(tmp.path());

        let (req, signature) = token_request("GET", &serde_json::json!({"path": SECRET_PATH}));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_body_omits(&body, &[SECRET_PATH, "ledger-2031", "not found"]);

        let reply = filebridge::stream::open_reply(TOKEN, &signature, &body).unwrap();
        assert_eq!(reply.status, 404);
        assert_eq!(reply.error.as_deref(), Some("path not found"));
        assert_eq!(reply.body, None);
    }

    #[tokio::test]
    async fn test_token_mode_error_does_not_decrypt_with_another_signature() {
        // The reply is bound to its request: a reply recorded for one request
        // cannot be passed off as the answer to another.
        let tmp = tempfile::tempdir().unwrap();
        let app = token_app(tmp.path());

        let (req, _) = token_request("GET", &serde_json::json!({"path": "nope.txt"}));
        let (_, other_signature) = token_request("GET", &serde_json::json!({"path": "nope.txt"}));
        let resp = app.oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(filebridge::stream::open_reply(TOKEN, &other_signature, &body).is_err());
    }

    #[tokio::test]
    async fn test_token_mode_info_and_listing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();

        let reply = token_reply(
            token_app(tmp.path()),
            token_request("GET", &serde_json::json!({"path": "a.txt"})),
        )
        .await;
        assert_eq!(reply.status, 200);
        let info = reply.body.unwrap();
        assert_eq!(info["name"], "a.txt");
        assert_eq!(info["size"], 5);

        let reply = token_reply(
            token_app(tmp.path()),
            token_request("GET", &serde_json::json!({"path": ""})),
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body.unwrap()["items"][0]["name"], "a.txt");
    }

    #[tokio::test]
    async fn test_token_mode_request_is_read_without_its_content_type() {
        // The Content-Type header is not signed. Without it the request must
        // still be answered for the path in its encrypted body, not with a
        // listing of the root.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();

        let (mut req, signature) = token_request("GET", &serde_json::json!({"path": "a.txt"}));
        req.headers_mut().remove("Content-Type");
        let reply = token_reply(token_app(tmp.path()), (req, signature)).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body.unwrap()["name"], "a.txt");

        // And a request without a body is not a listing either.
        let (builder, signature) = signed("GET");
        let req = builder.body(Body::empty()).unwrap();
        let reply = token_reply(token_app(tmp.path()), (req, signature)).await;
        assert_eq!(reply.status, 400);
    }

    #[tokio::test]
    async fn test_token_mode_accept_does_not_turn_metadata_into_content() {
        // The Accept header is not signed. If it decided what is sent, adding
        // it in transit would turn a request for metadata into a download,
        // and the size of that response shows that the path is a file and how
        // large it is.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), vec![b'x'; 100_000]).unwrap();

        for accept in [
            "application/vnd.filebridge.stream",
            "application/octet-stream",
        ] {
            let (mut req, signature) = token_request("GET", &serde_json::json!({"path": "a.txt"}));
            req.headers_mut().insert("Accept", accept.parse().unwrap());
            let reply = token_reply(token_app(tmp.path()), (req, signature)).await;
            assert_eq!(reply.status, 200, "{accept}");
            assert_eq!(reply.body.unwrap()["size"], 100_000, "{accept}");
        }
    }

    #[tokio::test]
    async fn test_token_mode_content_is_asked_for_in_the_encrypted_request() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();

        // Neither a missing Accept header nor one that asks for JSON turns the
        // request for content into one for metadata.
        for accept in [None, Some("application/json")] {
            let (mut req, signature) = token_request(
                "GET",
                &serde_json::json!({"path": "a.txt", "content": true}),
            );
            if let Some(accept) = accept {
                req.headers_mut().insert("Accept", accept.parse().unwrap());
            }
            let resp = token_app(tmp.path()).oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get("content-type").unwrap(),
                "application/vnd.filebridge.stream",
                "{accept:?}"
            );

            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let mut aead = filebridge::stream::StreamAead::new(TOKEN, &signature).unwrap();
            let mut decoder = filebridge::stream::StreamDecoder::new();
            decoder.push(&body);
            let Some(filebridge::stream::StreamFrame::Data { payload }) =
                decoder.next_frame().unwrap()
            else {
                panic!("expected a DATA frame");
            };
            let mut content = payload.to_vec();
            aead.decrypt(&mut content).unwrap();
            assert_eq!(content, b"hello");
        }

        // There is no content to send for a directory or a missing path. Both
        // are answered with a reply.
        let reply = token_reply(
            token_app(tmp.path()),
            token_request("GET", &serde_json::json!({"path": "", "content": true})),
        )
        .await;
        assert_eq!(reply.status, 200);
        assert!(reply.body.unwrap()["items"].is_array());

        let reply = token_reply(
            token_app(tmp.path()),
            token_request(
                "GET",
                &serde_json::json!({"path": "nope.txt", "content": true}),
            ),
        )
        .await;
        assert_eq!(reply.status, 404);
    }

    #[tokio::test]
    async fn test_token_mode_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let (builder, signature) = signed("OPTIONS");
        let req = builder.body(Body::empty()).unwrap();

        let reply = token_reply(token_app(tmp.path()), (req, signature)).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body.unwrap()["permissions"]["read"], true);
    }

    #[tokio::test]
    async fn test_token_mode_write_is_acknowledged_in_the_encrypted_reply() {
        // An empty success response could be made up by anyone on the path. The
        // acknowledgement of a write is an encrypted reply like every other.
        let tmp = tempfile::tempdir().unwrap();

        let reply = token_reply(token_app(tmp.path()), token_put("new.txt", b"payload")).await;
        assert_eq!(reply.status, 201);
        assert_eq!(reply.error, None);
        assert_eq!(
            std::fs::read(tmp.path().join("new.txt")).unwrap(),
            b"payload"
        );

        let reply = token_reply(token_app(tmp.path()), token_put("new.txt", b"again")).await;
        assert_eq!(reply.status, 200);
        assert_eq!(std::fs::read(tmp.path().join("new.txt")).unwrap(), b"again");
    }

    #[tokio::test]
    async fn test_token_mode_write_error_is_encrypted() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config_restricted(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some(TOKEN.to_string());

        let reply = token_reply(build_app(config), token_put("new.txt", b"payload")).await;
        assert_eq!(reply.status, 403);
        assert_eq!(reply.error.as_deref(), Some("write not allowed"));
        assert!(!tmp.path().join("new.txt").exists());
    }

    #[tokio::test]
    async fn test_token_mode_delete_is_acknowledged_in_the_encrypted_reply() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"payload").unwrap();

        let reply = token_reply(
            token_app(tmp.path()),
            token_request("DELETE", &serde_json::json!({"path": "old.txt"})),
        )
        .await;
        assert_eq!(reply.status, 204);
        assert!(!tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_token_mode_internal_error_is_encrypted() {
        let tmp = tempfile::tempdir().unwrap();
        // Deleting goes through `remove_file`, which fails on a directory.
        std::fs::create_dir(tmp.path().join("a.txt")).unwrap();

        let reply = token_reply(
            token_app(tmp.path()),
            token_request("DELETE", &serde_json::json!({"path": "a.txt"})),
        )
        .await;
        assert_eq!(reply.status, 500);
        assert_eq!(
            reply.error.as_deref(),
            Some("internal error; see the filebridged log for the cause")
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

    /// Asserts that `body` contains none of `needles`.
    fn assert_body_omits(body: &[u8], needles: &[&str]) {
        let text = String::from_utf8_lossy(body);
        for needle in needles {
            assert!(
                !text.contains(needle),
                "{needle:?} leaked in error body: {text:?}"
            );
        }
    }

    // Both tests below depend on a permission error, which root does not get.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_internal_error_body_does_not_leak_requested_path() {
        use std::os::unix::fs::PermissionsExt;

        if running_as_root() {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let unreadable = tmp.path().join("ledger-2031");
        std::fs::create_dir(&unreadable).unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().allow_recurse = true;
        let app = build_app(config);

        let req = Request::builder()
            .uri("/api/v1/fs/testloc/ledger-2031")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // The tempdir cannot be removed while the directory is unreadable.
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_body_omits(&body, &["ledger-2031"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_internal_error_body_does_not_leak_server_path() {
        if running_as_root() {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let mut config = test_config(tmp.path());
        // Handing a file to root fails for every other user.
        config
            .locations
            .get_mut("testloc")
            .unwrap()
            .file_permissions = Some(crate::config::FilePermissions {
            uid: Some(0),
            gid: None,
            mode: None,
        });
        let app = build_app(config);

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/ledger-2031.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_body_omits(&body, &["ledger-2031", root.to_str().unwrap()]);
    }

    #[tokio::test]
    async fn test_rename_token_mode_requires_target() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"payload").unwrap();

        // A plain envelope without `target`, which is what a DELETE would send.
        let reply = token_reply(
            token_app(tmp.path()),
            token_request("POST", &serde_json::json!({"path": "old.txt"})),
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_eq!(reply.error.as_deref(), Some("rename requires a target"));
        assert!(tmp.path().join("old.txt").exists());
    }

    #[tokio::test]
    async fn test_token_location_cannot_be_reached_under_an_encoded_name() {
        // The handlers see the percent-decoded location name. Every spelling
        // of it in the URL has to pass the same authentication.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let mut config = test_config(tmp.path());
        config.locations.get_mut("testloc").unwrap().token = Some("secret".to_string());
        let app = build_app(config);

        // `%63` is `c`.
        for (method, uri) in [
            ("GET", "/api/v1/fs/testlo%63"),
            ("GET", "/api/v1/fs/testlo%63/"),
            ("GET", "/api/v1/fs/testlo%63/a.txt"),
            ("HEAD", "/api/v1/fs/testlo%63/a.txt"),
            ("PUT", "/api/v1/fs/testlo%63/new.txt"),
            ("POST", "/api/v1/fs/testlo%63/a.txt?target=b.txt"),
            ("DELETE", "/api/v1/fs/testlo%63/a.txt"),
            ("OPTIONS", "/api/v1/fs/testlo%63"),
            ("GET", "/api/v1/fs/%74%65%73%74%6c%6f%63/a.txt"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("Accept", "application/octet-stream")
                .body(Body::from("planted"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            // A location with a token refuses HEAD before anything else.
            let expected = if method == "HEAD" {
                StatusCode::METHOD_NOT_ALLOWED
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(resp.status(), expected, "{method} {uri}");
        }

        assert_eq!(std::fs::read(tmp.path().join("a.txt")).unwrap(), b"hello");
        assert!(!tmp.path().join("new.txt").exists());
        assert!(!tmp.path().join("b.txt").exists());
    }

    #[tokio::test]
    async fn test_open_location_is_reachable_under_an_encoded_name() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .uri("/api/v1/fs/testlo%63/a.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Uploads replace the target only when they are complete
    // -----------------------------------------------------------------------

    /// Names in `dir`, to see that an upload left no temporary file behind.
    fn names_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// A token-mode upload of `content` to `path` that ends after its DATA
    /// frame, as it does when the connection breaks off.
    fn token_put_without_stop(path: &str, content: &[u8]) -> (Request<Body>, String) {
        let (builder, signature) = signed("PUT");
        let envelope = encrypt_envelope(&signature, &serde_json::json!({"path": path}));
        let mut aead = filebridge::stream::StreamAead::new(TOKEN, &signature).unwrap();
        let mut chunk = content.to_vec();
        aead.encrypt(&mut chunk).unwrap();

        let mut body = filebridge::stream::encode_meta(envelope.as_bytes());
        body.extend(filebridge::stream::encode_data(&chunk));
        let req = builder
            .header("Content-Type", "application/vnd.filebridge.stream")
            .body(Body::from(body))
            .unwrap();
        (req, signature)
    }

    #[tokio::test]
    async fn test_upload_that_breaks_off_leaves_the_file_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"old content").unwrap();

        let reply = token_reply(
            token_app(tmp.path()),
            token_put_without_stop("old.txt", b"new"),
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_eq!(
            std::fs::read(tmp.path().join("old.txt")).unwrap(),
            b"old content"
        );

        // A file that did not exist before does not exist afterwards.
        let reply = token_reply(
            token_app(tmp.path()),
            token_put_without_stop("new.txt", b"new"),
        )
        .await;
        assert_eq!(reply.status, 400);
        assert_eq!(names_in(tmp.path()), ["old.txt"]);
    }

    #[tokio::test]
    async fn test_upload_with_an_altered_frame_leaves_the_file_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"old content").unwrap();

        // Two DATA frames, the second one not authentic. The first one is
        // decrypted and written before the second one is looked at.
        let (builder, signature) = signed("PUT");
        let envelope = encrypt_envelope(&signature, &serde_json::json!({"path": "old.txt"}));
        let mut aead = filebridge::stream::StreamAead::new(TOKEN, &signature).unwrap();
        let mut first = b"new".to_vec();
        aead.encrypt(&mut first).unwrap();
        let mut body = filebridge::stream::encode_meta(envelope.as_bytes());
        body.extend(filebridge::stream::encode_data(&first));
        body.extend(filebridge::stream::encode_data(&[0u8; 32]));
        let req = builder
            .header("Content-Type", "application/vnd.filebridge.stream")
            .body(Body::from(body))
            .unwrap();

        let reply = token_reply(token_app(tmp.path()), (req, signature)).await;
        assert_eq!(reply.status, 400);
        assert_eq!(
            std::fs::read(tmp.path().join("old.txt")).unwrap(),
            b"old content"
        );
        assert_eq!(names_in(tmp.path()), ["old.txt"]);
    }

    #[tokio::test]
    async fn test_plain_upload_that_breaks_off_leaves_the_file_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("old.txt"), b"old content").unwrap();
        let app = build_app(test_config(tmp.path()));

        let chunks: [Result<&[u8], std::io::Error>; 2] =
            [Ok(b"new"), Err(std::io::Error::other("connection reset"))];
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/old.txt")
            .body(Body::from_stream(futures::stream::iter(chunks)))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(!resp.status().is_success());
        assert_eq!(
            std::fs::read(tmp.path().join("old.txt")).unwrap(),
            b"old content"
        );
        assert_eq!(names_in(tmp.path()), ["old.txt"]);
    }

    #[tokio::test]
    async fn test_upload_replaces_the_whole_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"a long old content").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from("new"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(std::fs::read(tmp.path().join("a.txt")).unwrap(), b"new");
        assert_eq!(names_in(tmp.path()), ["a.txt"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_upload_keeps_the_mode_of_the_file_it_replaces() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.txt");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from("new"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o640);
    }

    /// Starts an upload to `a.txt` and returns the mode of its temporary file
    /// while the upload waits for more data, then lets the upload finish.
    #[cfg(unix)]
    async fn mode_of_running_upload(config: Config, dir: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
        let chunks = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|chunk| (chunk, rx))
        });
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from_stream(chunks))
            .unwrap();
        let upload = tokio::spawn(build_app(config).oneshot(req));
        tx.send(Ok(b"new".to_vec())).await.unwrap();

        let temp = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let name = names_in(dir)
                    .into_iter()
                    .find(|name| name.starts_with(".filebridge-upload-"));
                if let Some(name) = name {
                    break dir.join(name);
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("no temporary file while the upload runs");
        let mode = std::fs::metadata(&temp).unwrap().permissions().mode() & 0o7777;

        drop(tx);
        let resp = upload.await.unwrap().unwrap();
        assert!(resp.status().is_success());
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"new");
        assert_eq!(names_in(dir), ["a.txt"]);
        mode
    }

    // The umask of the test run can clear further bits, so the tests look only
    // at the bits that must not be set.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_running_upload_is_not_more_readable_than_the_file_it_replaces() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.txt");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mode = mode_of_running_upload(test_config(tmp.path()), tmp.path()).await;
        assert_eq!(mode & !0o600, 0, "temporary file has mode {mode:o}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_running_upload_is_not_more_readable_than_the_location_allows() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config
            .locations
            .get_mut("testloc")
            .unwrap()
            .file_permissions = Some(crate::config::FilePermissions {
            uid: None,
            gid: None,
            mode: Some(0o640),
        });

        let mode = mode_of_running_upload(config, tmp.path()).await;
        assert_eq!(mode & !0o640, 0, "temporary file has mode {mode:o}");
        let mode = std::fs::metadata(tmp.path().join("a.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o640);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_upload_keeps_the_group_where_the_location_sets_only_the_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.txt");
        std::fs::write(&path, b"old").unwrap();
        // Needs a second group of the user, one that a new file does not get
        // anyway. `id` lists the groups on every Unix, nix does not.
        let default_gid = std::fs::metadata(&path).unwrap().gid();
        let groups = std::process::Command::new("id").arg("-G").output().unwrap();
        let Some(other) = String::from_utf8_lossy(&groups.stdout)
            .split_whitespace()
            .filter_map(|gid| gid.parse::<u32>().ok())
            .find(|gid| *gid != default_gid)
        else {
            return;
        };
        std::os::unix::fs::chown(&path, None, Some(other)).unwrap();

        let mut config = test_config(tmp.path());
        config
            .locations
            .get_mut("testloc")
            .unwrap()
            .file_permissions = Some(crate::config::FilePermissions {
            uid: None,
            gid: None,
            mode: Some(0o640),
        });
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from("new"))
            .unwrap();
        let resp = build_app(config).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.gid(), other);
        assert_eq!(meta.permissions().mode() & 0o7777, 0o640);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_upload_does_not_keep_the_setuid_bit_of_the_file_it_replaces() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.txt");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4750)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o4750);

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from("new"))
            .unwrap();
        let resp = build_app(test_config(tmp.path()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o750);
    }

    // That the data is on disk cannot be seen from here. The tests cover that
    // an upload with `fsync` works the same, replaced as a whole and in place.
    #[tokio::test]
    async fn test_upload_with_fsync() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"0123456789").unwrap();
        let synced = || {
            let mut config = test_config(tmp.path());
            config.locations.get_mut("testloc").unwrap().fsync = true;
            build_app(config)
        };
        let put = |uri: &str, content: &'static str| {
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/fs/testloc/{uri}"))
                .body(Body::from(content))
                .unwrap()
        };

        let resp = synced().oneshot(put("a.txt?offset=4", "xx")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            std::fs::read(tmp.path().join("a.txt")).unwrap(),
            b"0123xx6789"
        );

        let resp = synced().oneshot(put("a.txt", "new")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(std::fs::read(tmp.path().join("a.txt")).unwrap(), b"new");

        let resp = synced().oneshot(put("b.txt", "new")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(std::fs::read(tmp.path().join("b.txt")).unwrap(), b"new");
        assert_eq!(names_in(tmp.path()), ["a.txt", "b.txt"]);
    }

    #[tokio::test]
    async fn test_upload_with_offset_is_written_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"0123456789").unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt?offset=4")
            .body(Body::from("xx"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            std::fs::read(tmp.path().join("a.txt")).unwrap(),
            b"0123xx6789"
        );
    }

    #[tokio::test]
    async fn test_upload_does_not_replace_where_replace_is_not_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"old").unwrap();
        let create_only = || {
            let mut config = test_config(tmp.path());
            config.locations.get_mut("testloc").unwrap().allow_replace = false;
            build_app(config)
        };
        let put = |name: &str| {
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/fs/testloc/{name}"))
                .body(Body::from("new"))
                .unwrap()
        };

        let resp = create_only().oneshot(put("a.txt")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(std::fs::read(tmp.path().join("a.txt")).unwrap(), b"old");

        let resp = create_only().oneshot(put("b.txt")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(std::fs::read(tmp.path().join("b.txt")).unwrap(), b"new");
        assert_eq!(names_in(tmp.path()), ["a.txt", "b.txt"]);
    }

    #[tokio::test]
    async fn test_upload_to_the_name_of_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("docs")).unwrap();
        let app = build_app(test_config(tmp.path()));

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/docs")
            .body(Body::from("new"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(names_in(tmp.path()), ["docs"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_upload_whose_permissions_cannot_be_set_leaves_no_file() {
        if running_as_root() {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        // Handing a file to root fails for every other user.
        config
            .locations
            .get_mut("testloc")
            .unwrap()
            .file_permissions = Some(crate::config::FilePermissions {
            uid: Some(0),
            gid: None,
            mode: None,
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/fs/testloc/a.txt")
            .body(Body::from("payload"))
            .unwrap();
        let resp = build_app(config).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(names_in(tmp.path()), Vec::<String>::new());
    }
}
