mod config;
mod server;

use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use config::AppConfig;
use server::FilebridgeMcp;

#[tokio::main]
async fn main() -> Result<()> {
    // MCP uses stdout for JSON-RPC frames — all logging MUST go to stderr
    tracing_subscriber::registry()
        .with(EnvFilter::from_env("RUST_LOG"))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr),
        )
        .init();

    let config = AppConfig::from_env()?;
    let service = FilebridgeMcp::new(config);
    let server = service.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
