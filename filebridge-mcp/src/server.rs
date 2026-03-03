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
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());
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
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());
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
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());
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

    /// Delete a file from the filebridge location
    #[tool]
    async fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());
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
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());

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

        let data = match loc.read(&params.path, params.offset, params.length).await {
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
            _ => match String::from_utf8(data.clone()) {
                Ok(s) => {
                    let json = serde_json::json!({
                        "content": s,
                        "encoding": "text",
                        "size": s.len(),
                    });
                    CallToolResult::success(vec![Content::text(json.to_string())])
                }
                Err(_) => {
                    let json = serde_json::json!({
                        "content": BASE64.encode(&data),
                        "encoding": "base64",
                        "size": data.len(),
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
        let loc_cfg = match self.config.locations.get(&params.location) {
            Some(lc) => lc,
            None => return Ok(Self::loc_not_found(&params.location, &self.config)),
        };
        let loc = loc_cfg.client.location(&loc_cfg.location_id, loc_cfg.token.clone());

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
