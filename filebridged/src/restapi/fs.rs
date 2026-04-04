//! Filesystem utilities: path resolution, file open, directory listing, permissions.

use std::path::PathBuf;
use std::time::SystemTime;

use chrono::DateTime;

use crate::config::LocationEntry;
use crate::error::ApiError;
use crate::models::FileInfo;

pub fn resolve_canonical_write(
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
pub async fn open_for_write(
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

pub fn resolve_canonical_path(entry: &LocationEntry, filepath: &str) -> Result<PathBuf, ApiError> {
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

pub async fn list_directory(
    path: &std::path::Path,
    allow_recurse: bool,
    extensive: bool,
    hash_cache: &crate::cache::HashCache,
) -> Result<Vec<FileInfo>, ()> {
    let entries = path.read_dir().map_err(|_| ())?;

    struct CollectedEntry {
        name: String,
        is_dir: bool,
        size: Option<u64>,
        mtime: Option<String>,
        path: std::path::PathBuf,
    }

    // First pass: collect entries with metadata (no hashing yet)
    let mut collected: Vec<CollectedEntry> = vec![];

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
                let (size, mtime) = match entry.metadata() {
                    Ok(meta) => {
                        let size = if is_dir { None } else { Some(meta.len()) };
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|mt| mt.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .and_then(|d| DateTime::from_timestamp(d.as_secs() as i64, 0))
                            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                        (size, mtime)
                    }
                    Err(_) => (None, None),
                };
                collected.push(CollectedEntry {
                    name: name.to_string(),
                    is_dir,
                    size,
                    mtime,
                    path: entry.path(),
                });
            }
        }
    }

    // Second pass: compute hashes in parallel
    let hashes = futures::future::join_all(collected.iter().map(|e| {
        let is_dir = e.is_dir;
        let name = e.name.clone();
        let path = &e.path;
        async move {
            if extensive && !is_dir {
                match hash_cache.get_or_compute(path).await {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("hash computation failed for {name}: {e}");
                        None
                    }
                }
            } else {
                None
            }
        }
    }))
    .await;

    // Merge
    let files = collected
        .into_iter()
        .zip(hashes)
        .map(|(e, sha256)| FileInfo {
            name: e.name,
            is_dir: e.is_dir,
            size: e.size,
            mtime: e.mtime,
            sha256,
        })
        .collect();

    Ok(files)
}

#[cfg(unix)]
pub async fn apply_file_permissions(
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

pub async fn delete_file_inner(
    entry: &LocationEntry,
    filepath: &str,
    hash_cache: &crate::cache::HashCache,
) -> Result<axum::http::StatusCode, ApiError> {
    if !entry.allow_delete {
        return Err(ApiError::Forbidden("delete not allowed".into()));
    }

    let path = match resolve_canonical_path(entry, filepath) {
        Ok(p) => p,
        Err(ApiError::NotFound(_)) => return Ok(axum::http::StatusCode::NO_CONTENT),
        Err(e) => return Err(e),
    };

    match tokio::fs::remove_file(&path).await {
        Ok(_) => {
            hash_cache.invalidate(&path);
            Ok(axum::http::StatusCode::NO_CONTENT)
        }
        Err(e) => Err(ApiError::Internal(anyhow::anyhow!("remove file: {e}"))),
    }
}
