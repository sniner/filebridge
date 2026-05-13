//! Filesystem utilities: path resolution, file open, directory listing, permissions.

use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;

use crate::config::LocationEntry;
use crate::error::ApiError;
use crate::models::FileInfo;

pub async fn resolve_canonical_write(
    entry: &LocationEntry,
    filepath: &str,
) -> Result<PathBuf, ApiError> {
    // Lexical validation: reject `..`, absolute paths, prefixes — these would
    // let us escape the location root, and canonicalize() can't catch them
    // when we're about to create missing components.
    let rel = Path::new(filepath);
    for c in rel.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(ApiError::Forbidden("invalid path".into()));
        }
    }

    let full = entry.path.join(rel);
    let parent = full
        .parent()
        .ok_or(ApiError::Forbidden("no parent directory".into()))?;

    let canon_parent = match parent.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            // Parent does not exist — permission cascade for auto-mkdir.
            if !entry.allow_create {
                return Err(ApiError::Forbidden("create not allowed".into()));
            }
            if !entry.allow_recurse {
                return Err(ApiError::Forbidden("recurse not allowed".into()));
            }
            if !entry.allow_mkdir {
                return Err(ApiError::Forbidden("mkdir not allowed".into()));
            }
            create_missing_dirs(entry, parent).await?;
            parent
                .canonicalize()
                .map_err(|_| ApiError::Forbidden("path canonicalization failed".into()))?
        }
    };

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

/// Walk up from `parent` to the deepest existing ancestor, verify it is inside
/// the location root, and then create each missing component one level at a
/// time. We avoid `create_dir_all` so an unexpected symlink mid-path causes an
/// error instead of being silently traversed.
async fn create_missing_dirs(entry: &LocationEntry, parent: &Path) -> Result<(), ApiError> {
    let mut cursor = parent;
    let mut missing: Vec<&std::ffi::OsStr> = vec![];
    let canon_existing = loop {
        match cursor.canonicalize() {
            Ok(c) => break c,
            Err(_) => {
                let name = cursor
                    .file_name()
                    .ok_or(ApiError::Forbidden("invalid path component".into()))?;
                missing.push(name);
                cursor = cursor
                    .parent()
                    .ok_or(ApiError::Forbidden("no existing parent".into()))?;
            }
        }
    };

    if !canon_existing.starts_with(&entry.path) {
        return Err(ApiError::Forbidden("path outside allowed directory".into()));
    }

    let mut path = canon_existing;
    for name in missing.into_iter().rev() {
        path.push(name);
        match tokio::fs::create_dir(&path).await {
            Ok(()) => {
                #[cfg(unix)]
                if let Some(ref perms) = entry.file_permissions {
                    apply_dir_ownership(&path, perms).await?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Race: another writer beat us to it. Fine.
            }
            Err(e) => {
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "create_dir({:?}): {e}",
                    path
                )));
            }
        }
    }
    Ok(())
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

/// Apply only ownership (uid/gid) to a path, without touching mode.
/// Used on auto-created directories where the file mode would not be
/// meaningful (a file mode like 0o644 makes a directory unenterable).
#[cfg(unix)]
pub async fn apply_dir_ownership(
    path: &std::path::Path,
    perms: &crate::config::FilePermissions,
) -> Result<(), ApiError> {
    if perms.uid.is_none() && perms.gid.is_none() {
        return Ok(());
    }
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
    Ok(())
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
