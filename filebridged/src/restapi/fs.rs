//! Filesystem utilities: path resolution, file open, directory listing, permissions.

use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use chrono::DateTime;
use futures::StreamExt;

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

    let canon_parent = if let Ok(c) = parent.canonicalize() {
        c
    } else {
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
        if let Ok(c) = cursor.canonicalize() {
            break c;
        }
        let name = cursor
            .file_name()
            .ok_or(ApiError::Forbidden("invalid path component".into()))?;
        missing.push(name);
        cursor = cursor
            .parent()
            .ok_or(ApiError::Forbidden("no existing parent".into()))?;
    };

    if !canon_existing.starts_with(&entry.path) {
        return Err(ApiError::Forbidden("path outside allowed directory".into()));
    }

    let mut path = canon_existing;
    for name in missing.into_iter().rev() {
        path.push(name);
        match tokio::fs::create_dir(&path).await {
            Ok(()) =>
            {
                #[cfg(unix)]
                if let Some(ref perms) = entry.dir_permissions {
                    apply_permissions(&path, perms).await?;
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

/// Open a file for writing atomically, respecting the `allow_create` and `allow_replace` permissions.
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
                    return Err(ApiError::Forbidden(
                        "file exists, replace not allowed".into(),
                    ));
                }
                let f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(truncate)
                    .open(fpath)
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("open for write: {e}")))?;
                return Ok((f, false));
            }
            Err(e) => return Err(ApiError::Internal(anyhow::anyhow!("create file: {e}"))),
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::Forbidden(
                "file not found, create not allowed".into(),
            )),
            Err(e) => Err(ApiError::Internal(anyhow::anyhow!("open for write: {e}"))),
        }
    } else {
        Err(ApiError::Forbidden("write not allowed".into()))
    }
}

/// Start of the name of the temporary file an upload is written to.
const UPLOAD_PREFIX: &str = ".filebridge-upload-";

/// The file an upload is written to.
///
/// A write without an offset replaces the whole file. It goes to a temporary
/// file next to the target, which takes the target's name once the upload is
/// complete and verified. Until then the target is untouched, so an upload
/// that fails or breaks off leaves the old content, or no file, behind.
///
/// A write with an offset changes part of an existing file and is done in
/// place. If it fails, the file is left with whatever was written up to then.
pub struct WriteTarget {
    file: tokio::fs::File,
    path: PathBuf,
    created: bool,
    temp: Option<TempFile>,
    /// Metadata of the file that the upload replaces.
    replaced: Option<std::fs::Metadata>,
}

impl WriteTarget {
    /// Opens the file for an upload to `fpath`, checking the `allow_create`
    /// and `allow_replace` permissions of the location.
    pub async fn open(
        fpath: &Path,
        entry: &LocationEntry,
        offset: Option<u64>,
    ) -> Result<Self, ApiError> {
        if let Some(offset) = offset {
            use tokio::io::AsyncSeekExt;
            let (mut file, created) = open_for_write(fpath, entry, false).await?;
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("seek: {e}")))?;
            return Ok(Self::in_place(file, fpath, created));
        }

        let existing = tokio::fs::symlink_metadata(fpath).await.ok();
        match (&existing, entry.allow_create, entry.allow_replace) {
            (_, false, false) => return Err(ApiError::Forbidden("write not allowed".into())),
            (Some(_), _, false) => {
                return Err(ApiError::Forbidden(
                    "file exists, replace not allowed".into(),
                ));
            }
            (None, false, _) => {
                return Err(ApiError::Forbidden(
                    "file not found, create not allowed".into(),
                ));
            }
            _ => {}
        }
        if existing.as_ref().is_some_and(std::fs::Metadata::is_dir) {
            return Err(ApiError::Forbidden("target is a directory".into()));
        }

        let dir = fpath
            .parent()
            .ok_or(ApiError::Forbidden("no parent directory".into()))?;
        match TempFile::create(dir, upload_mode(entry, existing.as_ref())).await {
            Ok((temp, file)) => Ok(Self {
                file,
                path: fpath.to_owned(),
                created: existing.is_none(),
                temp: Some(temp),
                replaced: existing,
            }),
            // The daemon may be allowed to write a file but not to create one
            // in its directory. Then the upload is written in place and is not
            // atomic.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::debug!("no temporary file in {dir:?} ({e}), writing in place");
                let (file, created) = open_for_write(fpath, entry, true).await?;
                Ok(Self::in_place(file, fpath, created))
            }
            Err(e) => Err(ApiError::Internal(anyhow::anyhow!(
                "create temporary file: {e}"
            ))),
        }
    }

    fn in_place(file: tokio::fs::File, fpath: &Path, created: bool) -> Self {
        Self {
            file,
            path: fpath.to_owned(),
            created,
            temp: None,
            replaced: None,
        }
    }

    pub fn file_mut(&mut self) -> &mut tokio::fs::File {
        &mut self.file
    }

    /// Finishes a complete upload: sets the permissions and gives the file
    /// its name. Dropping the target instead discards the upload.
    pub async fn commit(self, entry: &LocationEntry) -> Result<axum::http::StatusCode, ApiError> {
        use tokio::io::AsyncWriteExt;
        let Self {
            mut file,
            path,
            created,
            temp,
            replaced,
        } = self;

        // A write to a tokio file may still be in progress when `write_all`
        // returns. `flush` waits for it and reports its error.
        file.flush()
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;

        #[cfg(unix)]
        {
            let written = temp.as_ref().map_or(path.as_path(), |t| t.path.as_path());
            // What the location does not set stays as it was on the replaced
            // file, as it would after a write in place.
            if let (Some(_), Some(old)) = (&temp, &replaced) {
                keep_attributes(written, old).await?;
            }
            if let Some(perms) = &entry.file_permissions {
                apply_permissions(written, perms).await?;
            }
        }
        #[cfg(not(unix))]
        let _ = replaced;

        // After the permissions, so that they are on disk with the content.
        if entry.fsync {
            file.sync_all()
                .await
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("sync file: {e}")))?;
        }
        // Windows does not rename a file that is open.
        drop(file);

        if let Some(temp) = temp {
            temp.publish(&path, entry.allow_replace).await?;
            if entry.fsync {
                sync_dir(&path).await?;
            }
        }
        Ok(if created {
            axum::http::StatusCode::CREATED
        } else {
            axum::http::StatusCode::OK
        })
    }
}

/// A temporary file that is removed when dropped, unless it was published.
struct TempFile {
    path: PathBuf,
    published: bool,
}

impl TempFile {
    /// Creates the file in `dir`, on Unix with `mode` if one is given. The
    /// umask can clear bits of it.
    async fn create(dir: &Path, mode: Option<u32>) -> std::io::Result<(Self, tokio::fs::File)> {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;

        loop {
            let name = format!("{UPLOAD_PREFIX}{:016x}", rand::random::<u64>());
            let path = dir.join(name);
            match options.open(&path).await {
                Ok(file) => {
                    let temp = Self {
                        path,
                        published: false,
                    };
                    return Ok((temp, file));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Gives the file the name `target`.
    async fn publish(mut self, target: &Path, replace: bool) -> Result<(), ApiError> {
        let exists = || ApiError::Forbidden("file exists, replace not allowed".into());

        if !replace {
            // `rename` replaces an existing target, and another upload may
            // have created it since the check in `WriteTarget::open`. A hard
            // link is refused when the name is taken. The temporary name is
            // removed on drop.
            match tokio::fs::hard_link(&self.path, target).await {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists()),
                // A filesystem without hard links: check and rename, with a
                // window between the two.
                Err(_) => {
                    if tokio::fs::symlink_metadata(target).await.is_ok() {
                        return Err(exists());
                    }
                }
            }
        }

        tokio::fs::rename(&self.path, target)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename upload: {e}")))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Also runs when the request is cancelled, where nothing can be
        // awaited. Removing one file does not block for long.
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::warn!("cannot remove temporary file {:?}: {e}", self.path);
        }
    }
}

/// Writes the directory of `path` to disk. A new name in a directory survives
/// a power failure only when the directory itself is synced.
#[cfg(unix)]
async fn sync_dir(path: &Path) -> Result<(), ApiError> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    let sync = async { tokio::fs::File::open(dir).await?.sync_all().await };
    sync.await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("sync directory: {e}")))
}

/// Windows cannot sync a directory and stores a rename with the file.
#[cfg(not(unix))]
async fn sync_dir(_path: &Path) -> Result<(), ApiError> {
    Ok(())
}

/// Mode to create the temporary file of an upload with: the mode of the
/// location, else that of the file the upload replaces.
///
/// The file holds the upload from its first byte, so it must not be readable
/// by more users than the target will be. `WriteTarget::commit` sets the exact
/// mode afterwards.
#[cfg(unix)]
fn upload_mode(entry: &LocationEntry, replaced: Option<&std::fs::Metadata>) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    entry
        .file_permissions
        .as_ref()
        .and_then(|perms| perms.mode)
        .or_else(|| replaced.map(MetadataExt::mode))
        .map(|mode| mode & 0o777)
}

#[cfg(not(unix))]
fn upload_mode(_entry: &LocationEntry, _replaced: Option<&std::fs::Metadata>) -> Option<u32> {
    None
}

/// Gives `path` the mode and, where the daemon is allowed to, the owner and
/// group of the file it replaces. Written in place, the file would have kept
/// them. The setuid, setgid and sticky bits are not carried over: the new
/// content is not what they were given to.
#[cfg(unix)]
async fn keep_attributes(path: &Path, old: &std::fs::Metadata) -> Result<(), ApiError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let (uid, gid, mode) = (old.uid(), old.gid(), old.mode() & 0o777);
    let owned = path.to_owned();
    tokio::task::spawn_blocking(move || {
        // Only root can give a file away. Without that right the file belongs
        // to the daemon's user; the group is kept where the user is in it.
        if std::os::unix::fs::chown(&owned, Some(uid), Some(gid)).is_err()
            && let Err(e) = std::os::unix::fs::chown(&owned, None, Some(gid))
        {
            tracing::debug!("cannot keep the group of {owned:?}: {e}");
        }
    })
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("spawn_blocking join: {e}")))?;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("chmod({path:?}, {mode:o}): {e}")))
}

pub fn resolve_canonical_path(entry: &LocationEntry, filepath: &str) -> Result<PathBuf, ApiError> {
    let full = entry.path.join(filepath);
    // Keep `filepath` out of the error message. Error bodies are rendered
    // verbatim and unencrypted by `impl IntoResponse for ApiError`, so echoing
    // the path would undo the very thing token mode buys by carrying it in an
    // encrypted envelope. Operators still see it: every handler logs the path
    // via `tracing::info!` before reaching this point.
    let canon = full
        .canonicalize()
        .map_err(|_| ApiError::NotFound("path not found".into()))?;
    if !canon.starts_with(&entry.path)
        || (!entry.allow_recurse
            && canon != entry.path
            && canon.parent() != Some(entry.path.as_path()))
    {
        return Err(ApiError::Forbidden("path outside allowed directory".into()));
    }
    Ok(canon)
}

/// The modification time of a file in the format of the API: UTC, to the
/// second.
pub fn mtime_string(metadata: &std::fs::Metadata) -> Option<String> {
    let since_epoch = metadata
        .modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?;
    let mtime = DateTime::from_timestamp(i64::try_from(since_epoch.as_secs()).ok()?, 0)?;
    Some(mtime.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// An entry of a directory before its hash is known.
struct ListedEntry {
    name: String,
    is_dir: bool,
    size: Option<u64>,
    mtime: Option<String>,
    path: PathBuf,
}

/// The files of a directory and, with `allow_recurse`, its subdirectories.
///
/// Symbolic links are left out, so that a listing does not lead out of the
/// location. So is everything that is neither a file nor a directory, and
/// every name that is not valid UTF-8.
fn read_entries(path: &Path, allow_recurse: bool) -> Result<Vec<ListedEntry>, ()> {
    let mut listed = vec![];
    for entry in path.read_dir().map_err(|_| ())?.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let is_dir = file_type.is_dir();
        if !is_dir && !file_type.is_file() {
            continue;
        }
        if is_dir && !allow_recurse {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };

        let (size, mtime) = match entry.metadata() {
            Ok(meta) => ((!is_dir).then_some(meta.len()), mtime_string(&meta)),
            Err(_) => (None, None),
        };
        listed.push(ListedEntry {
            name,
            is_dir,
            size,
            mtime,
            path: entry.path(),
        });
    }
    Ok(listed)
}

/// The SHA-256 hash of every file in `entries`, in their order. A directory
/// has none, and neither has a file whose hash could not be computed.
async fn hash_entries(
    entries: &[ListedEntry],
    hash_cache: &crate::cache::HashCache,
) -> Vec<Option<String>> {
    /// Upper bound for simultaneously open files during hashing — decouples
    /// fd usage from directory size (see fd-exhaustion incident 2026-07-15).
    const MAX_CONCURRENT_HASHES: usize = 32;

    // An unbounded join_all opens every file in the directory at once, which
    // exhausts the process fd limit on large directories (EMFILE at accept).
    // Collected first: `buffered` over the lazy iterator does not compile,
    // the closure is not general enough in the lifetime of its argument.
    let hash_futures: Vec<_> = entries
        .iter()
        .map(|entry| async move {
            if entry.is_dir {
                None
            } else {
                Some(hash_cache.get_or_compute(&entry.path).await)
            }
        })
        .collect();
    let outcomes: Vec<Option<std::io::Result<String>>> = futures::stream::iter(hash_futures)
        .buffered(MAX_CONCURRENT_HASHES)
        .collect()
        .await;

    // One summary line instead of a warning per file: a persistent error
    // state (e.g. EMFILE) must not flood the journal on every listing.
    let mut failed = 0usize;
    let mut first_failure: Option<(&str, std::io::Error)> = None;
    let hashes = outcomes
        .into_iter()
        .zip(entries)
        .map(|(outcome, entry)| match outcome? {
            Ok(hash) => Some(hash),
            Err(err) => {
                failed += 1;
                first_failure.get_or_insert((entry.name.as_str(), err));
                None
            }
        })
        .collect();
    if let Some((name, err)) = first_failure {
        tracing::warn!("hash computation failed for {failed} file(s), first: {name}: {err}");
    }
    hashes
}

pub async fn list_directory(
    path: &std::path::Path,
    allow_recurse: bool,
    extensive: bool,
    hash_cache: &crate::cache::HashCache,
) -> Result<Vec<FileInfo>, ()> {
    let entries = read_entries(path, allow_recurse)?;
    let hashes = if extensive {
        hash_entries(&entries, hash_cache).await
    } else {
        vec![None; entries.len()]
    };

    let files = entries
        .into_iter()
        .zip(hashes)
        .map(|(entry, sha256)| FileInfo {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
            mtime: entry.mtime,
            sha256,
        })
        .collect();
    Ok(files)
}

#[cfg(unix)]
pub async fn apply_permissions(
    path: &std::path::Path,
    perms: &crate::config::FilePermissions,
) -> Result<(), ApiError> {
    if let Some(mode_bits) = perms.mode {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode_bits);
        tokio::fs::set_permissions(path, permissions)
            .await
            .map_err(|e| {
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
        Ok(()) => {
            hash_cache.invalidate(&path);
            Ok(axum::http::StatusCode::NO_CONTENT)
        }
        Err(e) => Err(ApiError::Internal(anyhow::anyhow!("remove file: {e}"))),
    }
}

/// Rename (move) a file within a location.
///
/// Only regular files are supported. Windows' `MOVEFILE_REPLACE_EXISTING` — which
/// `std::fs::rename` uses to give POSIX-like replace semantics — does not apply to
/// directories, so allowing them here would make the operation behave differently
/// per platform.
pub async fn rename_inner(
    entry: &LocationEntry,
    from: &str,
    to: &str,
    hash_cache: &crate::cache::HashCache,
) -> Result<axum::http::StatusCode, ApiError> {
    // A rename makes one entry appear and another disappear, so it needs the
    // rights for both halves. This is why there is no separate `allow_rename`.
    if !entry.allow_create {
        return Err(ApiError::Forbidden("create not allowed".into()));
    }
    if !entry.allow_delete {
        return Err(ApiError::Forbidden("delete not allowed".into()));
    }

    // Source must exist; a missing source is a 404 rather than a silent success,
    // unlike DELETE which is idempotent.
    let src = resolve_canonical_path(entry, from)?;
    if src.is_dir() {
        return Err(ApiError::Forbidden("directory rename not supported".into()));
    }

    // Validates the target lexically, canonicalizes its parent, rejects symlinks
    // and runs the auto-mkdir cascade.
    let dst = resolve_canonical_write(entry, to).await?;

    // `rename` replaces the target silently, which would let a create-only
    // location (allow_create without allow_replace) overwrite existing files —
    // exactly what `open_for_write` refuses. There is a TOCTOU window between
    // this check and the rename; closing it needs `renameat2(RENAME_NOREPLACE)`
    // or link+unlink, neither of which is portable across the filesystems a
    // location may live on. Since exploiting it requires create rights on the
    // location already, the check is a permission guard, not a race-free
    // guarantee.
    if !entry.allow_replace && tokio::fs::symlink_metadata(&dst).await.is_ok() && src != dst {
        return Err(ApiError::Forbidden(
            "target exists, replace not allowed".into(),
        ));
    }

    tokio::fs::rename(&src, &dst)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;

    // Both paths change identity: the source is gone, the target has new content.
    // A stale entry would hand out a wrong SHA-256 on the next `extensive` listing.
    hash_cache.invalidate(&src);
    hash_cache.invalidate(&dst);

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hashes are computed by a bounded stream and merged back via zip,
    /// so this guards the name<->hash alignment: replacing `buffered` with
    /// `buffer_unordered` would silently attach hashes to the wrong files.
    #[tokio::test]
    async fn test_list_directory_extensive_hashes_align_with_names() {
        use sha2::{Digest, Sha256};

        let tmp = tempfile::tempdir().unwrap();
        for i in 0..100 {
            std::fs::write(
                tmp.path().join(format!("f{i:03}.txt")),
                format!("content {i}"),
            )
            .unwrap();
        }
        let cache = crate::cache::HashCache::new();
        let files = list_directory(tmp.path(), false, true, &cache)
            .await
            .unwrap();
        assert_eq!(files.len(), 100);
        for f in files {
            let expected = hex::encode(Sha256::digest(
                std::fs::read(tmp.path().join(&f.name)).unwrap(),
            ));
            assert_eq!(
                f.sha256.as_deref(),
                Some(expected.as_str()),
                "hash mismatch for {}",
                f.name
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_list_directory_entries() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("a.txt"), tmp.path().join("link")).unwrap();
        let locked = tmp.path().join("locked.txt");
        std::fs::write(&locked, b"secret").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let cache = crate::cache::HashCache::new();
        let sorted = |mut files: Vec<FileInfo>| {
            files.sort_by(|a, b| a.name.cmp(&b.name));
            files
        };

        // Without recursion: no directory. A link is never listed.
        let files = sorted(
            list_directory(tmp.path(), false, true, &cache)
                .await
                .unwrap(),
        );
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "locked.txt"]);
        assert_eq!(files[0].size, Some(5));
        assert!(files[0].sha256.is_some());
        assert!(files[0].mtime.is_some());
        // A file that cannot be hashed is listed without its hash.
        assert_eq!(files[1].size, Some(6));
        if !nix::unistd::geteuid().is_root() {
            assert_eq!(files[1].sha256, None);
        }

        let files = sorted(
            list_directory(tmp.path(), true, false, &cache)
                .await
                .unwrap(),
        );
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "locked.txt", "sub"]);
        assert!(files[2].is_dir);
        assert_eq!(files[2].size, None);
        assert!(files.iter().all(|f| f.sha256.is_none()));
    }
}
