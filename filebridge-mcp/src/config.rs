use std::collections::HashMap;

use anyhow::{Context, Result};
use filebridge::FileBridgeClient;
use serde::Deserialize;

pub struct LocationConfig {
    pub client: FileBridgeClient,
    /// Server-side location name (used in the `/api/v1/fs/{name}` URL).
    pub name: String,
    pub token: Option<String>,
}

pub struct AppConfig {
    /// Keyed by the MCP-local lookup name (the `alias` if set, else the
    /// server-side `name`).
    pub locations: HashMap<String, LocationConfig>,
    pub read_size_limit: usize,
    pub glob_max_results: usize,
}

#[derive(Deserialize)]
struct TomlLocationEntry {
    /// Server-side location name.
    name: String,
    /// Optional MCP-local shortcut; if omitted, `name` is used.
    alias: Option<String>,
    base_url: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct TomlConfig {
    location: Vec<TomlLocationEntry>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let read_size_limit = std::env::var("FILEBRIDGE_READ_SIZE_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        let glob_max_results = std::env::var("FILEBRIDGE_GLOB_MAX_RESULTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);

        let mut locations = HashMap::new();

        if let Ok(config_path) = std::env::var("FILEBRIDGE_MCP_CONFIG") {
            let content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {config_path}"))?;
            let toml_config: TomlConfig =
                toml::from_str(&content).context("Failed to parse TOML config")?;
            for entry in toml_config.location {
                let client = FileBridgeClient::new(&entry.base_url)
                    .with_context(|| format!("Invalid base_url for location '{}'", entry.name))?;
                let lookup_key = entry.alias.unwrap_or_else(|| entry.name.clone());
                locations.insert(
                    lookup_key,
                    LocationConfig {
                        client,
                        name: entry.name,
                        token: entry.token,
                    },
                );
            }
        } else {
            let base_url = std::env::var("FILEBRIDGE_BASE_URL")
                .context("FILEBRIDGE_BASE_URL is required (or set FILEBRIDGE_MCP_CONFIG)")?;
            let token = std::env::var("FILEBRIDGE_TOKEN").ok();
            let name = std::env::var("FILEBRIDGE_LOCATION_NAME")
                .unwrap_or_else(|_| "default".to_string());
            let lookup_key = std::env::var("FILEBRIDGE_LOCATION_ALIAS")
                .unwrap_or_else(|_| name.clone());

            let client = FileBridgeClient::new(&base_url).context("Invalid FILEBRIDGE_BASE_URL")?;
            locations.insert(
                lookup_key,
                LocationConfig {
                    client,
                    name,
                    token,
                },
            );
        }

        Ok(AppConfig {
            locations,
            read_size_limit,
            glob_max_results,
        })
    }
}
