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
    #[cfg(unix)]
    pub dir_permissions: Option<FilePermissions>,
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
    pub dir_owner: Option<String>,
    pub dir_group: Option<String>,
    pub dir_mode: Option<String>,
}

/// Default mode applied to newly written files when any permission field is
/// configured for the location and `file_mode` is not set explicitly.
const DEFAULT_FILE_MODE: u32 = 0o644;
/// Default mode applied to auto-created directories when any permission field
/// is configured for the location and `dir_mode` is not set explicitly.
const DEFAULT_DIR_MODE: u32 = 0o755;

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
            if let Some(ref m) = raw.dir_mode {
                parse_octal_mode(m)?;
            }

            #[cfg(unix)]
            let (file_permissions, dir_permissions) = {
                let any_perm = raw.file_owner.is_some()
                    || raw.file_group.is_some()
                    || raw.file_mode.is_some()
                    || raw.dir_owner.is_some()
                    || raw.dir_group.is_some()
                    || raw.dir_mode.is_some();

                if !any_perm {
                    (None, None)
                } else {
                    let file_uid = raw.file_owner.as_deref().map(resolve_uid).transpose()?;
                    let file_gid = raw.file_group.as_deref().map(resolve_gid).transpose()?;
                    let file_mode = raw
                        .file_mode
                        .as_deref()
                        .map(parse_octal_mode)
                        .transpose()?
                        .unwrap_or(DEFAULT_FILE_MODE);

                    // dir_owner/dir_group fall back to file_owner/file_group;
                    // if neither is set, dir ownership is left untouched.
                    let dir_uid = match raw.dir_owner.as_deref() {
                        Some(s) => Some(resolve_uid(s)?),
                        None => file_uid,
                    };
                    let dir_gid = match raw.dir_group.as_deref() {
                        Some(s) => Some(resolve_gid(s)?),
                        None => file_gid,
                    };
                    let dir_mode = raw
                        .dir_mode
                        .as_deref()
                        .map(parse_octal_mode)
                        .transpose()?
                        .unwrap_or(DEFAULT_DIR_MODE);

                    (
                        Some(FilePermissions {
                            uid: file_uid,
                            gid: file_gid,
                            mode: Some(file_mode),
                        }),
                        Some(FilePermissions {
                            uid: dir_uid,
                            gid: dir_gid,
                            mode: Some(dir_mode),
                        }),
                    )
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
                #[cfg(unix)]
                dir_permissions,
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

    #[cfg(unix)]
    #[test]
    fn no_perms_means_none() {
        let toml = r#"
            [[location]]
            name = "loc"
            path = "/tmp"
        "#;
        let cfg = Config::from_str(toml).unwrap();
        let loc = cfg.get_location("loc").unwrap();
        assert!(loc.file_permissions.is_none());
        assert!(loc.dir_permissions.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn dir_perms_fallback_from_file() {
        // Numeric UID/GID skips name resolution so the test is hermetic.
        let toml = r#"
            [[location]]
            name = "loc"
            path = "/tmp"
            file_owner = "1000"
            file_group = "1000"
        "#;
        let cfg = Config::from_str(toml).unwrap();
        let loc = cfg.get_location("loc").unwrap();
        let fp = loc.file_permissions.as_ref().expect("file_permissions");
        assert_eq!(fp.uid, Some(1000));
        assert_eq!(fp.gid, Some(1000));
        assert_eq!(fp.mode, Some(DEFAULT_FILE_MODE));
        let dp = loc.dir_permissions.as_ref().expect("dir_permissions");
        assert_eq!(dp.uid, Some(1000));
        assert_eq!(dp.gid, Some(1000));
        assert_eq!(dp.mode, Some(DEFAULT_DIR_MODE));
    }

    #[cfg(unix)]
    #[test]
    fn dir_perms_explicit_overrides_file() {
        let toml = r#"
            [[location]]
            name = "loc"
            path = "/tmp"
            file_owner = "1000"
            file_mode = "600"
            dir_owner = "1001"
            dir_mode = "750"
        "#;
        let cfg = Config::from_str(toml).unwrap();
        let loc = cfg.get_location("loc").unwrap();
        let fp = loc.file_permissions.as_ref().unwrap();
        assert_eq!(fp.uid, Some(1000));
        assert_eq!(fp.mode, Some(0o600));
        let dp = loc.dir_permissions.as_ref().unwrap();
        assert_eq!(dp.uid, Some(1001));
        assert_eq!(dp.mode, Some(0o750));
    }

    #[cfg(unix)]
    #[test]
    fn dir_mode_only_still_triggers_perms() {
        // Even if only `dir_mode` is set, both perm structs should be populated
        // with their defaults so file writes also get a deterministic mode.
        let toml = r#"
            [[location]]
            name = "loc"
            path = "/tmp"
            dir_mode = "700"
        "#;
        let cfg = Config::from_str(toml).unwrap();
        let loc = cfg.get_location("loc").unwrap();
        let fp = loc.file_permissions.as_ref().unwrap();
        assert_eq!(fp.uid, None);
        assert_eq!(fp.gid, None);
        assert_eq!(fp.mode, Some(DEFAULT_FILE_MODE));
        let dp = loc.dir_permissions.as_ref().unwrap();
        assert_eq!(dp.mode, Some(0o700));
    }

    #[test]
    fn invalid_dir_mode_rejected() {
        let toml = r#"
            [[location]]
            name = "loc"
            path = "/tmp"
            dir_mode = "9zz"
        "#;
        assert!(Config::from_str(toml).is_err());
    }
}
