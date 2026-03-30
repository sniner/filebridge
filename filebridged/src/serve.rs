use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::restapi::routes;

#[derive(Parser, Debug)]
#[command(name = "filebridged", version, about = "Filebridge REST API Daemon")]
pub struct Args {
    /// Port, default: 8000
    #[arg(long, default_value = "8000")]
    pub port: u16,

    /// Log level filter (e.g. "info", "debug", "filebridged=debug")
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Log file path (stderr receives only errors when set)
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Path to configuration file
    #[arg(value_name = "CONFIG")]
    pub config_path: PathBuf,
}

/// Normalize common log level aliases that tracing doesn't recognize.
fn normalize_log_level(input: &str) -> String {
    // EnvFilter accepts complex directives like "filebridged=debug,tower=warn".
    // We only normalize bare words that look like level aliases but aren't
    // valid tracing levels (tracing uses "warn", not "warning").
    input
        .split(',')
        .map(|part| {
            let trimmed = part.trim();
            // Only normalize bare level words, not target=level pairs
            if !trimmed.contains('=') {
                match trimmed.to_lowercase().as_str() {
                    "warning" => "warn".to_string(),
                    "critical" => "error".to_string(),
                    _ => trimmed.to_string(),
                }
            } else {
                trimmed.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub async fn run_server_from_args() -> anyhow::Result<()> {
    let args = Args::parse();

    let log_level = normalize_log_level(&args.log_level);
    let env_filter = EnvFilter::try_new(&log_level)
        .map_err(|e| anyhow::anyhow!("invalid --log-level {:?}: {e}", args.log_level))?;

    if let Some(ref log_file) = args.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;

        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .with_filter(env_filter);

        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(EnvFilter::new("error"));

        tracing_subscriber::registry()
            .with(file_layer)
            .with(stderr_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
            .init();
    }

    let config = Config::load(&args.config_path)?;
    let app = routes(config);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
