use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mdate: Option<String>,
    pub sha256: Option<String>,
}
