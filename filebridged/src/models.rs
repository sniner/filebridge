use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub mdate: Option<String>,
    pub sha256: Option<String>,
}
