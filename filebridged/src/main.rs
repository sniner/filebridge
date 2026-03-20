mod auth;
mod cache;
mod config;
mod models;
mod restapi;
mod serve;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve::run_server_from_args().await
}
pub mod nonce;
