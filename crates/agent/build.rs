//! Build script: copies agent_key.bin and agent_cfg.bin from OUT_DIR
//! into the directory that include_bytes! can reach.
//!
//! When invoked by ghoststrike-builder, OUT_DIR is set to the temp dir
//! containing the per-build key and config.  For a plain `cargo build`
//! we write placeholder bytes so the binary still compiles.

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let key_path = out_dir.join("agent_key.bin");
    let cfg_path = out_dir.join("agent_cfg.bin");

    // Write placeholder files if the builder hasn't provided real ones.
    if !key_path.exists() {
        std::fs::write(&key_path, vec![0u8; 32]).unwrap();
    }
    if !cfg_path.exists() {
        // Minimal valid config for a dev build.
        let placeholder = serde_json::json!({
            "c2_host":    "127.0.0.1",
            "c2_port":    8080,
            "protocol":   "http",
            "sleep_ms":   5000,
            "jitter_pct": 10,
            "dns_domain": null,
            "pipe_name":  null,
            "build_id":   "dev-build"
        });
        let plain = serde_json::to_vec(&placeholder).unwrap();
        // XOR with the placeholder key (all zeros → identity)
        std::fs::write(&cfg_path, &plain).unwrap();
    }

    // Rerun if the builder drops new files.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GHOSTSTRIKE_BUILD_ID");
    println!("cargo:rerun-if-changed={}", key_path.display());
    println!("cargo:rerun-if-changed={}", cfg_path.display());
}
