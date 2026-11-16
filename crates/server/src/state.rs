use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;
use anyhow::Result;

use ghoststrike_common::{AgentInfo, ListenerConfig, SessionKey, Task, OperatorMsg, x25519_generate};

use crate::config::ServerConfig;
use crate::db::Db;

pub type SharedState = Arc<ServerState>;

pub struct ServerState {
    pub config:    ServerConfig,
    pub db:        Option<Db>,
    pub agents:    RwLock<HashMap<Uuid, AgentInfo>>,
    pub listeners: RwLock<HashMap<Uuid, ListenerConfig>>,
    pub tasks:     RwLock<HashMap<Uuid, Vec<Task>>>,  // agent_id -> pending tasks
    /// Broadcast channel — all operator connections subscribe to this.
    pub broadcast: broadcast::Sender<OperatorMsg>,
    /// Listener shutdown handles: listener_id -> shutdown tx
    pub listener_handles: RwLock<HashMap<Uuid, tokio::sync::oneshot::Sender<()>>>,
    // ── ECDH ──────────────────────────────────────────────────────────────────
    /// Server x25519 static private key bytes (kept in memory only).
    pub server_priv: [u8; 32],
    /// Server x25519 static public key bytes (baked into agent payloads).
    pub server_pub:  [u8; 32],
    /// Per-agent AES-GCM session keys derived via ECDH.
    pub agent_keys:  RwLock<HashMap<Uuid, SessionKey>>,
}

impl ServerState {
    pub async fn new(config: ServerConfig) -> Result<Arc<Self>> {
        let (tx, _) = broadcast::channel(256);

        let db = match Db::open(&config.db_path).await {
            Ok(d)  => { tracing::info!("SQLite db opened: {}", config.db_path); Some(d) }
            Err(e) => { tracing::warn!("SQLite unavailable ({e}), using in-memory only"); None }
        };

        // Resolve server x25519 keypair: load from config or generate fresh.
        let (server_priv, server_pub) = if config.server_privkey.is_empty() {
            let (priv_b, pub_b) = x25519_generate();
            tracing::info!(
                "Generated server x25519 keypair (pubkey: {}). \
                 Add server_privkey = \"{}\" to server.toml to persist.",
                hex::encode(pub_b),
                hex::encode(priv_b),
            );
            (priv_b, pub_b)
        } else {
            let raw = hex::decode(&config.server_privkey)
                .expect("server_privkey must be valid hex");
            let mut priv_b = [0u8; 32];
            priv_b.copy_from_slice(&raw);
            use x25519_dalek::{StaticSecret, PublicKey as X25519Pub};
            let pub_b = *X25519Pub::from(&StaticSecret::from(priv_b)).as_bytes();
            tracing::info!("Loaded server x25519 pubkey: {}", hex::encode(pub_b));
            (priv_b, pub_b)
        };

        let state = Arc::new(Self {
            config,
            db,
            agents:           RwLock::new(HashMap::new()),
            listeners:        RwLock::new(HashMap::new()),
            tasks:            RwLock::new(HashMap::new()),
            broadcast:        tx,
            listener_handles: RwLock::new(HashMap::new()),
            server_priv,
            server_pub,
            agent_keys:       RwLock::new(HashMap::new()),
        });

        // Restore persisted agents from DB.
        // Restore persisted agents from DB.
        if let Some(ref db) = state.db {
            if let Ok(agents) = db.list_agents().await {
                let mut map = state.agents.write().await;
                for a in agents {
                    map.insert(a.id, a);
                }
            }
        }

        Ok(state)
    }

    pub async fn upsert_agent(&self, info: AgentInfo) {
        if let Some(ref db) = self.db {
            let _ = db.upsert_agent(&info).await;
        }
        let _ = self.broadcast.send(OperatorMsg::AgentCheckin { agent: info.clone() });
        self.agents.write().await.insert(info.id, info);
    }

    pub async fn pending_tasks_for(&self, agent_id: Uuid) -> Vec<Task> {
        self.tasks
            .read()
            .await
            .get(&agent_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.status == ghoststrike_common::TaskStatus::Pending)
            .collect()
    }

    pub async fn queue_task(&self, task: Task) {
        if let Some(ref db) = self.db {
            let _ = db.insert_task(&task).await;
        }
        let agent_id = task.agent_id;
        let mut tasks = self.tasks.write().await;
        tasks.entry(agent_id).or_default().push(task);
    }

    pub async fn update_task_result(
        &self,
        agent_id: Uuid,
        task_id: Uuid,
        output: String,
        success: bool,
    ) {
        use ghoststrike_common::TaskStatus;
        use chrono::Utc;
        let status = if success { TaskStatus::Completed } else { TaskStatus::Failed };
        let done   = Utc::now();

        if let Some(ref db) = self.db {
            let _ = db.update_task(task_id, &status, Some(&output), Some(done)).await;
        }

        let mut tasks = self.tasks.write().await;
        if let Some(list) = tasks.get_mut(&agent_id) {
            if let Some(t) = list.iter_mut().find(|t| t.id == task_id) {
                t.status       = status;
                t.output       = Some(output);
                t.completed_at = Some(done);
                let _ = self.broadcast.send(OperatorMsg::TaskResult { task: t.clone() });
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<OperatorMsg> {
        self.broadcast.subscribe()
    }

    pub async fn list_agents(&self) -> Vec<AgentInfo> {
        self.agents.read().await.values().cloned().collect()
    }

    pub async fn list_listeners(&self) -> Vec<ListenerConfig> {
        self.listeners.read().await.values().cloned().collect()
    }
}
