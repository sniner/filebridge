use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::restapi::routes;

#[derive(Parser, Debug)]
#[command(name = "filebridged", version, about = "Filebridge REST API Daemon")]
pub struct Args {
    /// Port, default: 8000
    #[arg(long, default_value = "8000")]
    pub port: u16,

    /// Path to configuration file
    #[arg(value_name = "CONFIG")]
    pub config_path: PathBuf,
}

pub async fn run_server_from_args() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load(&args.config_path)?;
    let app = routes(config);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
