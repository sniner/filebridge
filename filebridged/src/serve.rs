use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal;
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

    let listener = bind_with_keepalive(addr)?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Shutdown complete");
    Ok(())
}

/// Bind the listener with TCP keepalive enabled. Accepted sockets inherit
/// the option, so half-open connections from vanished clients are reaped by
/// the kernel instead of holding their file descriptors forever.
fn bind_with_keepalive(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};

    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // Tokio's TcpListener::bind sets SO_REUSEADDR on Unix; keep that behaviour.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_mins(1))
        .with_interval(Duration::from_secs(15));
    socket.set_tcp_keepalive(&keepalive)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

/// Resolve when SIGINT or SIGTERM is received. Used to trigger a graceful
/// shutdown: the listener stops accepting new connections, in-flight
/// requests are allowed to finish, then `axum::serve` returns. If the
/// process is still alive after the container's grace period, the runtime
/// (e.g. Docker) will follow up with SIGKILL.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!("failed to install SIGINT handler: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("SIGINT received, draining in-flight requests");
        }
        _ = terminate => {
            tracing::info!("SIGTERM received, draining in-flight requests");
        }
    }
}
