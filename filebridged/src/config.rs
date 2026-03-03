use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct LocationEntry {
    pub label: String,
    pub path: PathBuf,
    #[serde(default = "default_true")]
    pub allow_read: bool,
    #[serde(default = "default_true")]
    pub allow_create: bool,
    #[serde(default)]
    pub allow_replace: bool,
    #[serde(default = "default_true")]
    pub allow_inspect: bool,
    #[serde(default)]
    pub allow_delete: bool,
    #[serde(default)]
    pub allow_recurse: bool,
    pub token: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct ConfigToml {
    #[serde(rename = "location")]
    pub locations: Vec<LocationEntry>,
}

#[derive(Debug)]
pub struct Config {
    pub locations: HashMap<String, LocationEntry>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if path.is_dir() {
            let mut entries = vec![];
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let p = entry.path();
                if let Some(ext) = p.extension().and_then(|s| s.to_str())
                    && (ext == "toml" || ext == "conf") {
                        entries.push(p);
                    }
            }
            entries.sort();
            let mut merged = String::new();
            for entry in entries {
                merged.push_str(&fs::read_to_string(entry)?);
                merged.push('\n');
            }
            Self::from_str(&merged)
        } else {
            let content = fs::read_to_string(path)?;
            Self::from_str(&content)
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        let parsed: ConfigToml = toml::from_str(s)?;
        let mut map = HashMap::new();
        for mut loc in parsed.locations {
            if let Ok(canon) = loc.path.canonicalize() {
                loc.path = canon;
            }
            if loc.path.is_dir() {
                map.insert(loc.label.to_lowercase(), loc);
            }
        }
        Ok(Self { locations: map })
    }

    pub fn get_location(&self, dir_id: &str) -> Option<&LocationEntry> {
        self.locations.get(&dir_id.to_lowercase())
    }
}
