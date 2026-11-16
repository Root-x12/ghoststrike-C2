/// HTTPS listener — self-signed cert generated at start (rcgen), or loaded from paths in config.
use anyhow::Result;
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::oneshot;
use tracing::info;

use crate::state::SharedState;
use super::http::agent_router;

pub async fn start(
    state: SharedState,
    cfg: ghoststrike_common::ListenerConfig,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let addr = format!("{}:{}", cfg.host, cfg.port).parse()?;

    // Generate or load TLS certificate.
    let tls_cfg = build_tls_config(&cfg.host).await?;
    let app     = agent_router(state);

    let handle = tokio::spawn(async move {
        info!("HTTPS listener on {addr}");
        axum_server::bind_rustls(addr, tls_cfg)
            .handle(axum_server::Handle::new())
            .serve(app.into_make_service())
            .await
            .ok();
        // Graceful shutdown via dropping the handle is handled externally;
        // for the demo we just drop the task on shutdown_rx.
        drop(shutdown_rx);
        info!("HTTPS listener shut down");
    });

    Ok(handle)
}

async fn build_tls_config(host: &str) -> Result<RustlsConfig> {
    // Self-signed cert for the given hostname.
    let cert = rcgen::generate_simple_self_signed(vec![host.to_string()])?;
    let cert_pem = cert.serialize_pem()?.into_bytes();
    let key_pem  = cert.serialize_private_key_pem().into_bytes();

    Ok(RustlsConfig::from_pem(cert_pem, key_pem).await?)
}
