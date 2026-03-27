use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mtime: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
}
