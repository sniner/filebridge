//! Data models returned by the Filebridge API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// File or directory metadata returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Entry name (file or directory name, not the full path).
    pub name: String,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
    /// File size in bytes. `None` for directories.
    pub size: Option<u64>,
    /// Last modification time.
    pub mtime: Option<DateTime<Utc>>,
    /// SHA-256 hash of the file content. Only present with
    /// [`info_extensive`](crate::FileBridgeLocation::info_extensive).
    pub sha256: Option<String>,
}

/// Permissions granted to the client for a specific location.
///
/// Returned by [`FileBridgeLocation::permissions`](crate::FileBridgeLocation::permissions).
/// All fields reflect the server-side configuration; clients can use them
/// to short-circuit operations they aren't allowed to perform, but the
/// server remains the source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub create: bool,
    pub replace: bool,
    pub inspect: bool,
    pub delete: bool,
    pub recurse: bool,
    pub mkdir: bool,
}
