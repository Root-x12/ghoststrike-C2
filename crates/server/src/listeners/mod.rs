mod http;
mod https;
mod dns;
mod smb;

use anyhow::{bail, Result};
use uuid::Uuid;
use tracing::info;

use ghoststrike_common::{ListenerConfig, ListenerProtocol, OperatorMsg};
use crate::state::SharedState;

pub async fn start(state: SharedState, mut cfg: ListenerConfig) -> Result<ListenerConfig> {
    cfg.id = Uuid::new_v4();
    cfg.active = true;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handle = match cfg.protocol {
        ListenerProtocol::Http  => http::start(state.clone(), cfg.clone(), shutdown_rx).await?,
        ListenerProtocol::Https => https::start(state.clone(), cfg.clone(), shutdown_rx).await?,
        ListenerProtocol::Dns   => dns::start(state.clone(), cfg.clone(), shutdown_rx).await?,
        ListenerProtocol::Smb   => smb::start(state.clone(), cfg.clone(), shutdown_rx).await?,
    };

    // Drop the JoinHandle — listener runs until shutdown_tx fires.
    drop(handle);

    state.listeners.write().await.insert(cfg.id, cfg.clone());
    state.listener_handles.write().await.insert(cfg.id, shutdown_tx);

    info!(
        "[{}] Listener {} started on {}:{}",
        cfg.protocol, cfg.name, cfg.host, cfg.port
    );

    let _ = state.broadcast.send(OperatorMsg::ListenerStarted { config: cfg.clone() });
    Ok(cfg)
}

pub async fn stop(state: SharedState, id: Uuid) -> Result<()> {
    let tx = state.listener_handles.write().await.remove(&id);
    match tx {
        Some(tx) => {
            let _ = tx.send(());
            state.listeners.write().await.remove(&id);
            let _ = state.broadcast.send(OperatorMsg::ListenerStopped { id });
            info!("Listener {id} stopped");
            Ok(())
        }
        None => bail!("Listener {id} not found"),
    }
}
