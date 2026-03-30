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
