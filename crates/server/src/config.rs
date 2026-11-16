use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_host:      String,
    pub operator_port:  u16,
    pub agent_port:     u16,
    pub password:       String,
    pub db_path:        String,
    pub tls_cert:       Option<String>,
    pub tls_key:        Option<String>,
    pub server_name:    String,
    /// Hex-encoded 32-byte AES-GCM key shared with agents. Empty = plaintext.
    #[serde(default)]
    pub c2_key:         String,
    /// Hex-encoded 32-byte x25519 static private key.
    /// Auto-generated if empty; set to persist the keypair across restarts
    /// (required so agents built against the old pubkey can still connect).
    #[serde(default)]
    pub server_privkey: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_host:     "0.0.0.0".into(),
            operator_port: 8443,
            agent_port:    8080,
            password:      "ghoststrike".into(),
            db_path:       "ghoststrike.db".into(),
            tls_cert:      None,
            tls_key:       None,
            server_name:   "GhostStrike C2".into(),
            c2_key:        String::new(),
            server_privkey: String::new(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self> {
        if Path::new(path).exists() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading config {path}"))?;
            toml::from_str(&raw).with_context(|| "parsing config")
        } else {
            let cfg = Self::default();
            let raw = toml::to_string_pretty(&cfg)?;
            std::fs::write(path, raw)?;
            tracing::warn!("No config found — wrote default to {path}");
            Ok(cfg)
        }
    }
}
