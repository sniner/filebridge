use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo, ToolsCapability,
    },
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::config::AppConfig;

pub struct FilebridgeMcp {
    tool_router: ToolRouter<Self>,
    config: Arc<AppConfig>,
}

impl FilebridgeMcp {
    pub fn new(config: AppConfig) -> Self {
        Self {
            tool_router: Self::tool_router(),
            config: Arc::new(config),
        }
    }

    fn loc_not_found(location: &str, config: &AppConfig) -> CallToolResult {
        let names: Vec<&str> = config.locations.keys().map(|s| s.as_str()).collect();
        CallToolResult::error(vec![Content::text(format!(
            "Unknown location '{location}'. Available: {names:?}"
        ))])
    }

    fn get_location(
        &self,
        name: &str,
    ) -> Result<filebridge::FileBridgeLocation<'_>, CallToolResult> {
        let loc_cfg = self
            .config
            .locations
            .get(name)
            .ok_or_else(|| Self::loc_not_found(name, &self.config))?;
        Ok(loc_cfg
            .client
            .location(&loc_cfg.name, loc_cfg.token.clone()))
    }

    fn map_fb_error(e: filebridge::Error) -> Vec<Content> {
        match e {
            filebridge::Error::Api(status, msg) if status.as_u16() == 404 => {
                vec![Content::text(format!("Not found: {msg}"))]
            }
            filebridge::Error::Api(status, msg) if status.as_u16() == 403 => {
                vec![Content::text(format!("Access denied: {msg}"))]
            }
            filebridge::Error::IsDirectory => vec![Content::text("Target is a directory")],
            filebridge::Error::Hmac => {
                vec![Content::text("Authentication failed (HMAC mismatch)")]
            }
            e => vec![Content::text(format!("Error: {e}"))],
        }
    }
}

// ── Parameter structs ──────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct FileExistsParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the file or directory to check
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct GetInfoParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the file or directory
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListDirectoryParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the directory to list; omit or leave empty for root listing
    pub path: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeleteFileParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the file to delete
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReadFileParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the file to read
    pub path: String,
    /// Encoding for the returned content: "auto" (default), "text", or "base64"
    pub encoding: Option<String>,
    /// Byte offset to start reading from
    pub offset: Option<u64>,
    /// Number of bytes to read
    pub length: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GlobFilesParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Glob pattern to match against. Supports `*`, `?`, `[abc]`, and `**` (recursive).
    /// Examples: `*.txt`, `src/**/*.rs`, `data/[0-9]*.csv`
    pub pattern: String,
    /// Maximum number of entries to return; results beyond this are truncated.
    /// Defaults to the server-side `FILEBRIDGE_GLOB_MAX_RESULTS` setting.
    pub max_results: Option<usize>,
    /// If `true`, include full metadata (mtime, sha256) per entry.
    /// Defaults to `false` (compact: path, is_dir, size only).
    pub detailed: Option<bool>,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Any,
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SortKey {
    Name,
    Size,
    Mtime,
}

#[derive(Deserialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Order {
    Asc,
    Desc,
}

#[derive(Deserialize, JsonSchema)]
pub struct QueryFilesParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Directory to query; omit or leave empty for the location root.
    /// Ignored when `pattern` is set.
    pub path: Option<String>,
    /// Optional glob pattern (e.g. `**/*.rs`, `data/*.csv`).
    /// When set, takes precedence over `path` and can match recursively.
    pub pattern: Option<String>,
    /// Restrict to `file`, `dir`, or `any` (default).
    pub kind: Option<EntryKind>,
    /// Inclusive lower bound on file size in bytes.
    pub min_size: Option<u64>,
    /// Inclusive upper bound on file size in bytes.
    pub max_size: Option<u64>,
    /// Inclusive ISO-8601 lower bound on mtime
    /// (e.g. `2026-05-13` or `2026-05-13T08:00:00Z`).
    pub modified_after: Option<String>,
    /// Inclusive ISO-8601 upper bound on mtime.
    pub modified_before: Option<String>,
    /// Sort the result by `name`, `size`, or `mtime`. Entries missing the
    /// sort key are placed last.
    pub sort_by: Option<SortKey>,
    /// Sort order: `asc` (default) or `desc`.
    pub order: Option<Order>,
    /// Maximum number of entries to return; surplus entries are truncated.
    pub limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
pub struct WriteFileParams {
    /// Name of the filebridge location to use
    pub location: String,
    /// Path of the file to write
    pub path: String,
    /// Content to write
    pub content: String,
    /// Encoding of the provided content: "text" (default) or "base64"
    pub encoding: Option<String>,
    /// Byte offset to write at
    pub offset: Option<u64>,
}

// ── Tool implementations ───────────────────────────────────────────────────────

#[tool_router]
impl FilebridgeMcp {
    /// Check whether a file or directory exists at the given path
    #[tool]
    async fn file_exists(
        &self,
        Parameters(params): Parameters<FileExistsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };
        let result = match loc.info(&params.path).await {
            Ok(meta) => {
                let json = serde_json::json!({"exists": true, "is_dir": meta.is_dir});
                CallToolResult::success(vec![Content::text(json.to_string())])
            }
            Err(filebridge::Error::Api(status, _)) if status.as_u16() == 404 => {
                let json = serde_json::json!({"exists": false});
                CallToolResult::success(vec![Content::text(json.to_string())])
            }
            Err(e) => CallToolResult::error(Self::map_fb_error(e)),
        };
        Ok(result)
    }

    /// Get metadata (size, modification date, SHA-256) for a file or directory
    #[tool]
    async fn get_info(
        &self,
        Parameters(params): Parameters<GetInfoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };
        let result = match loc.info(&params.path).await {
            Ok(meta) => match serde_json::to_string(&meta) {
                Ok(json) => CallToolResult::success(vec![Content::text(json)]),
                Err(e) => CallToolResult::error(vec![Content::text(format!(
                    "Failed to serialize metadata: {e}"
                ))]),
            },
            Err(e) => CallToolResult::error(Self::map_fb_error(e)),
        };
        Ok(result)
    }

    /// List the contents of a directory
    #[tool]
    async fn list_directory(
        &self,
        Parameters(params): Parameters<ListDirectoryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };
        let path = params.path.as_deref().filter(|p| !p.is_empty());
        let result = match loc.list(path).await {
            Ok(items) => match serde_json::to_string(&items) {
                Ok(json) => CallToolResult::success(vec![Content::text(json)]),
                Err(e) => CallToolResult::error(vec![Content::text(format!(
                    "Failed to serialize listing: {e}"
                ))]),
            },
            Err(e) => CallToolResult::error(Self::map_fb_error(e)),
        };
        Ok(result)
    }

    /// Match files in the filebridge location against a glob pattern.
    /// Supports `*`, `?`, `[abc]` and recursive `**` (e.g. `src/**/*.rs`).
    /// Expansion happens client-side, so very broad patterns can be expensive —
    /// prefer narrowing with a path prefix when possible.
    #[tool]
    async fn glob_files(
        &self,
        Parameters(params): Parameters<GlobFilesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };

        let entries = match loc.glob(&params.pattern).await {
            Ok(e) => e,
            Err(e) => return Ok(CallToolResult::error(Self::map_fb_error(e))),
        };

        let limit = params.max_results.unwrap_or(self.config.glob_max_results);
        let total = entries.len();
        let truncated = total > limit;
        let detailed = params.detailed.unwrap_or(false);

        let items: Vec<serde_json::Value> = entries
            .into_iter()
            .take(limit)
            .map(|entry| {
                if detailed {
                    serde_json::json!({
                        "path": entry.path,
                        "metadata": entry.metadata,
                    })
                } else {
                    serde_json::json!({
                        "path": entry.path,
                        "is_dir": entry.metadata.is_dir,
                        "size": entry.metadata.size,
                    })
                }
            })
            .collect();

        let json = serde_json::json!({
            "matches": items,
            "count": items.len(),
            "total": total,
            "truncated": truncated,
        });

        let result = match serde_json::to_string(&json) {
            Ok(s) => CallToolResult::success(vec![Content::text(s)]),
            Err(e) => CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize glob results: {e}"
            ))]),
        };
        Ok(result)
    }

    /// Filter, sort, and limit entries in a location — the LLM-friendly
    /// alternative to listing then post-processing. Combine `pattern` for
    /// path/recursion, `kind`/`min_size`/`max_size`/`modified_after`/
    /// `modified_before` for filtering, and `sort_by`/`order`/`limit` for
    /// ranking. All filters are AND-combined.
    #[tool]
    async fn query_files(
        &self,
        Parameters(params): Parameters<QueryFilesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };

        let after = match params.modified_after.as_deref().map(parse_iso_bound).transpose() {
            Ok(v) => v,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid modified_after: {e}"
                ))]));
            }
        };
        let before = match params.modified_before.as_deref().map(parse_iso_bound).transpose() {
            Ok(v) => v,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid modified_before: {e}"
                ))]));
            }
        };

        // Source: pattern wins; otherwise list the (sub)directory.
        let entries: Vec<(String, filebridge::Metadata)> = if let Some(ref pat) = params.pattern {
            match loc.glob(pat).await {
                Ok(v) => v.into_iter().map(|e| (e.path, e.metadata)).collect(),
                Err(e) => return Ok(CallToolResult::error(Self::map_fb_error(e))),
            }
        } else {
            let path = params.path.as_deref().filter(|p| !p.is_empty());
            match loc.list(path).await {
                Ok(v) => v.into_iter().map(|m| (m.name.clone(), m)).collect(),
                Err(e) => return Ok(CallToolResult::error(Self::map_fb_error(e))),
            }
        };

        let kind = params.kind.unwrap_or(EntryKind::Any);
        let mut filtered: Vec<(String, filebridge::Metadata)> = entries
            .into_iter()
            .filter(|(_, m)| match kind {
                EntryKind::Any => true,
                EntryKind::File => !m.is_dir,
                EntryKind::Dir => m.is_dir,
            })
            .filter(|(_, m)| match params.min_size {
                Some(min) => m.size.map(|s| s >= min).unwrap_or(false),
                None => true,
            })
            .filter(|(_, m)| match params.max_size {
                Some(max) => m.size.map(|s| s <= max).unwrap_or(false),
                None => true,
            })
            .filter(|(_, m)| match (after, m.mtime) {
                (Some(bound), Some(mt)) => mt >= bound,
                (Some(_), None) => false,
                _ => true,
            })
            .filter(|(_, m)| match (before, m.mtime) {
                (Some(bound), Some(mt)) => mt <= bound,
                (Some(_), None) => false,
                _ => true,
            })
            .collect();

        if let Some(key) = params.sort_by {
            let desc = params.order == Some(Order::Desc);
            filtered.sort_by(|(a_path, a), (b_path, b)| {
                // `none_dominant` means the order between `a` and `b` is
                // determined by one being None — that ordering must NOT be
                // reversed when desc is set, otherwise None entries would
                // jump to the front of a descending list.
                let (ord, none_dominant) = match key {
                    SortKey::Name => (a_path.cmp(b_path), false),
                    SortKey::Size => (
                        cmp_some_first(a.size, b.size),
                        a.size.is_none() ^ b.size.is_none(),
                    ),
                    SortKey::Mtime => (
                        cmp_some_first(a.mtime, b.mtime),
                        a.mtime.is_none() ^ b.mtime.is_none(),
                    ),
                };
                if desc && !none_dominant { ord.reverse() } else { ord }
            });
        }

        let total = filtered.len();
        let limit = params.limit.unwrap_or(usize::MAX);
        let truncated = total > limit;
        filtered.truncate(limit);

        let items: Vec<serde_json::Value> = filtered
            .into_iter()
            .map(|(path, m)| {
                serde_json::json!({
                    "path": path,
                    "is_dir": m.is_dir,
                    "size": m.size,
                    "mtime": m.mtime,
                })
            })
            .collect();

        let json = serde_json::json!({
            "matches": items,
            "count": items.len(),
            "total": total,
            "truncated": truncated,
        });

        let result = match serde_json::to_string(&json) {
            Ok(s) => CallToolResult::success(vec![Content::text(s)]),
            Err(e) => CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize query results: {e}"
            ))]),
        };
        Ok(result)
    }

    /// Delete a file from the filebridge location
    #[tool]
    async fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };
        let result = match loc.delete(&params.path).await {
            Ok(()) => CallToolResult::success(vec![Content::text(format!(
                "Deleted: {}",
                params.path
            ))]),
            Err(e) => CallToolResult::error(Self::map_fb_error(e)),
        };
        Ok(result)
    }

    /// Read a file from the filebridge location. Returns content as text or base64.
    #[tool]
    async fn read_file(
        &self,
        Parameters(params): Parameters<ReadFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };

        // Size check when no offset/length is specified
        let read_size_limit = self.config.read_size_limit;
        if params.offset.is_none() && params.length.is_none() {
            match loc.info(&params.path).await {
                Ok(meta) => {
                    if let Some(size) = meta.size
                        && size as usize > read_size_limit {
                            return Ok(CallToolResult::error(vec![Content::text(format!(
                                "File too large ({size} bytes). Use offset/length or increase FILEBRIDGE_READ_SIZE_LIMIT."
                            ))]));
                        }
                }
                Err(filebridge::Error::Api(status, msg)) if status.as_u16() == 404 => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Not found: {msg}"
                    ))]));
                }
                Err(e) => return Ok(CallToolResult::error(Self::map_fb_error(e))),
            }
        }

        let data = match (params.offset, params.length) {
            (Some(off), Some(len)) => loc.read_range(&params.path, off, len).await,
            (None, None) => loc.read(&params.path).await,
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Both offset and length are required for partial reads",
                )]));
            }
        };
        let data = match data {
            Ok(d) => d,
            Err(e) => return Ok(CallToolResult::error(Self::map_fb_error(e))),
        };

        let encoding = params.encoding.as_deref().unwrap_or("auto");
        let result = match encoding {
            "base64" => {
                let json = serde_json::json!({
                    "content": BASE64.encode(&data),
                    "encoding": "base64",
                    "size": data.len(),
                });
                CallToolResult::success(vec![Content::text(json.to_string())])
            }
            "text" => match String::from_utf8(data) {
                Ok(s) => {
                    let json = serde_json::json!({
                        "content": s,
                        "encoding": "text",
                        "size": s.len(),
                    });
                    CallToolResult::success(vec![Content::text(json.to_string())])
                }
                Err(_) => CallToolResult::error(vec![Content::text(
                    "File is not valid UTF-8. Use encoding=base64.",
                )]),
            },
            // "auto" or anything else
            _ => match String::from_utf8(data) {
                Ok(s) => {
                    let json = serde_json::json!({
                        "content": s,
                        "encoding": "text",
                        "size": s.len(),
                    });
                    CallToolResult::success(vec![Content::text(json.to_string())])
                }
                Err(e) => {
                    let bytes = e.into_bytes();
                    let json = serde_json::json!({
                        "content": BASE64.encode(&bytes),
                        "encoding": "base64",
                        "size": bytes.len(),
                    });
                    CallToolResult::success(vec![Content::text(json.to_string())])
                }
            },
        };
        Ok(result)
    }

    /// Write content to a file in the filebridge location
    #[tool]
    async fn write_file(
        &self,
        Parameters(params): Parameters<WriteFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match self.get_location(&params.location) {
            Ok(l) => l,
            Err(r) => return Ok(r),
        };

        let encoding = params.encoding.as_deref().unwrap_or("text");
        let data: Vec<u8> = match encoding {
            "base64" => match BASE64.decode(&params.content) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Invalid base64 content: {e}"
                    ))]))
                }
            },
            _ => params.content.into_bytes(),
        };

        let result = match loc.write(&params.path, &data, params.offset).await {
            Ok(()) => CallToolResult::success(vec![Content::text(format!(
                "Written {} bytes to {}",
                data.len(),
                params.path
            ))]),
            Err(e) => CallToolResult::error(Self::map_fb_error(e)),
        };
        Ok(result)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Parse an ISO-8601 bound: either a full RFC 3339 timestamp or a bare
/// `YYYY-MM-DD` date (interpreted as the start of the day in UTC).
fn parse_iso_bound(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    use chrono::{NaiveDate, TimeZone, Utc};
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        && let Some(naive) = d.and_hms_opt(0, 0, 0)
    {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    Err(format!("expected ISO-8601 date or timestamp, got: {s:?}"))
}

/// Order Option values so that Some entries come before None.
fn cmp_some_first<T: Ord>(a: Option<T>, b: Option<T>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Some(av), Some(bv)) => av.cmp(&bv),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

// ── ServerHandler impl ─────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for FilebridgeMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability::default()),
                ..Default::default()
            },
            server_info: Implementation {
                name: "filebridge-mcp".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "Access files on a Filebridge server. Available locations: ".to_string()
                    + &self
                        .config
                        .locations
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
            ),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::cmp::Ordering;

    #[test]
    fn parse_iso_bound_rfc3339() {
        let got = parse_iso_bound("2026-05-13T08:00:00Z").unwrap();
        assert_eq!(got, Utc.with_ymd_and_hms(2026, 5, 13, 8, 0, 0).unwrap());
    }

    #[test]
    fn parse_iso_bound_bare_date() {
        let got = parse_iso_bound("2026-05-13").unwrap();
        assert_eq!(got, Utc.with_ymd_and_hms(2026, 5, 13, 0, 0, 0).unwrap());
    }

    #[test]
    fn parse_iso_bound_rejects_garbage() {
        assert!(parse_iso_bound("not a date").is_err());
        assert!(parse_iso_bound("13/05/2026").is_err());
    }

    #[test]
    fn cmp_some_first_orders_none_last() {
        assert_eq!(cmp_some_first(Some(1u64), Some(2)), Ordering::Less);
        assert_eq!(cmp_some_first(Some(2u64), Some(1)), Ordering::Greater);
        assert_eq!(cmp_some_first(Some(1u64), None), Ordering::Less);
        assert_eq!(cmp_some_first(None::<u64>, Some(1)), Ordering::Greater);
        assert_eq!(cmp_some_first(None::<u64>, None), Ordering::Equal);
    }
}
