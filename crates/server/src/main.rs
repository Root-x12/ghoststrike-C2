mod config;
mod state;
mod operators;
mod agents;
mod listeners;
mod db;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::ServerConfig;
use crate::state::ServerState;

#[derive(Parser)]
#[command(name = "ghoststrike-server", version)]
struct Args {
    /// Path to server config file
    #[arg(short, long, default_value = "server.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("ghoststrike_server=info".parse()?))
        .init();

    let args = Args::parse();
    let cfg  = ServerConfig::load(&args.config)?;

    info!("GhostStrike C2 Server starting — bind {}", cfg.bind_host);

    let state = ServerState::new(cfg.clone()).await?;

    // Start the operator WebSocket + agent HTTP API
    operators::serve(state.clone(), &cfg).await?;

    Ok(())
}
