use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;
use anyhow::Result;

use ghoststrike_common::{AgentInfo, ListenerConfig, Task, OperatorMsg};

use crate::config::ServerConfig;

pub type SharedState = Arc<ServerState>;

#[derive(Debug)]
pub struct ServerState {
    pub config:    ServerConfig,
    pub agents:    RwLock<HashMap<Uuid, AgentInfo>>,
    pub listeners: RwLock<HashMap<Uuid, ListenerConfig>>,
    pub tasks:     RwLock<HashMap<Uuid, Vec<Task>>>,  // agent_id -> pending tasks
    /// Broadcast channel — all operator connections subscribe to this.
    pub broadcast: broadcast::Sender<OperatorMsg>,
    /// Listener shutdown handles: listener_id -> shutdown tx
    pub listener_handles: RwLock<HashMap<Uuid, tokio::sync::oneshot::Sender<()>>>,
}

impl ServerState {
    pub async fn new(config: ServerConfig) -> Result<Arc<Self>> {
        let (tx, _) = broadcast::channel(256);
        Ok(Arc::new(Self {
            config,
            agents:           RwLock::new(HashMap::new()),
            listeners:        RwLock::new(HashMap::new()),
            tasks:            RwLock::new(HashMap::new()),
            broadcast:        tx,
            listener_handles: RwLock::new(HashMap::new()),
        }))
    }

    pub async fn upsert_agent(&self, info: AgentInfo) {
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
        let mut tasks = self.tasks.write().await;
        if let Some(list) = tasks.get_mut(&agent_id) {
            if let Some(t) = list.iter_mut().find(|t| t.id == task_id) {
                t.status       = if success { TaskStatus::Completed } else { TaskStatus::Failed };
                t.output       = Some(output);
                t.completed_at = Some(Utc::now());
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
