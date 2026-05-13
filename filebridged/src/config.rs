use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct FilePermissions {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
}

#[derive(Debug)]
pub struct LocationEntry {
    pub name: String,
    pub path: PathBuf,
    pub allow_read: bool,
    pub allow_create: bool,
    pub allow_replace: bool,
    pub allow_inspect: bool,
    pub allow_delete: bool,
    pub allow_recurse: bool,
    pub allow_mkdir: bool,
    pub token: Option<String>,
    #[cfg(unix)]
    pub file_permissions: Option<FilePermissions>,
}

#[derive(Debug, Deserialize)]
struct LocationEntryRaw {
    // TODO: remove the `label` alias once existing deployments have migrated
    // to `name` (target: 0.3.x).
    #[serde(alias = "label")]
    pub name: String,
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
    #[serde(default)]
    pub allow_mkdir: bool,
    pub token: Option<String>,
    pub file_owner: Option<String>,
    pub file_group: Option<String>,
    pub file_mode: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct ConfigToml {
    #[serde(rename = "location")]
    pub locations: Vec<LocationEntryRaw>,
}

#[derive(Debug)]
pub struct Config {
    pub locations: HashMap<String, LocationEntry>,
}

fn parse_octal_mode(s: &str) -> Result<u32> {
    let s = s.trim_start_matches('0');
    let s = if s.is_empty() { "0" } else { s };
    u32::from_str_radix(s, 8)
        .map_err(|_| anyhow::anyhow!("Invalid octal mode: '{}'", s))
}

#[cfg(unix)]
fn resolve_uid(s: &str) -> Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    use nix::unistd::User;
    User::from_name(s)?
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| anyhow::anyhow!("Unknown user: '{}'", s))
}

#[cfg(unix)]
fn resolve_gid(s: &str) -> Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    use nix::unistd::Group;
    Group::from_name(s)?
        .map(|g| g.gid.as_raw())
        .ok_or_else(|| anyhow::anyhow!("Unknown group: '{}'", s))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if path.is_dir() {
            let mut entries = vec![];
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let p = entry.path();
                if let Some(ext) = p.extension().and_then(|s| s.to_str())
                    && (ext == "toml" || ext == "conf")
                {
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
        for raw in parsed.locations {
            // Validate mode syntax on all platforms (fail fast)
            if let Some(ref m) = raw.file_mode {
                parse_octal_mode(m)?;
            }

            #[cfg(unix)]
            let file_permissions = {
                let uid = raw.file_owner.as_deref().map(resolve_uid).transpose()?;
                let gid = raw.file_group.as_deref().map(resolve_gid).transpose()?;
                let mode = raw.file_mode.as_deref().map(parse_octal_mode).transpose()?;
                if uid.is_none() && gid.is_none() && mode.is_none() {
                    None
                } else {
                    Some(FilePermissions { uid, gid, mode })
                }
            };

            let mut loc = LocationEntry {
                name: raw.name,
                path: raw.path,
                allow_read: raw.allow_read,
                allow_create: raw.allow_create,
                allow_replace: raw.allow_replace,
                allow_inspect: raw.allow_inspect,
                allow_delete: raw.allow_delete,
                allow_recurse: raw.allow_recurse,
                allow_mkdir: raw.allow_mkdir,
                token: raw.token,
                #[cfg(unix)]
                file_permissions,
            };
            if let Ok(canon) = loc.path.canonicalize() {
                loc.path = canon;
            }
            if loc.path.is_dir() {
                map.insert(loc.name.to_lowercase(), loc);
            }
        }
        Ok(Self { locations: map })
    }

    pub fn get_location(&self, dir_id: &str) -> Option<&LocationEntry> {
        self.locations.get(&dir_id.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_alias_still_parses() {
        // Migration bridge: configs written before the rename used `label`.
        // Keep this working until the alias is removed.
        let toml = r#"
            [[location]]
            label = "old-config"
            path = "/tmp"
        "#;
        let parsed: ConfigToml = toml::from_str(toml).unwrap();
        assert_eq!(parsed.locations.len(), 1);
        assert_eq!(parsed.locations[0].name, "old-config");
    }

    #[test]
    fn name_field_parses() {
        let toml = r#"
            [[location]]
            name = "new-config"
            path = "/tmp"
        "#;
        let parsed: ConfigToml = toml::from_str(toml).unwrap();
        assert_eq!(parsed.locations[0].name, "new-config");
    }
}
