/// SMB named-pipe listener (Windows host only).
///
/// On non-Windows the listener is a stub that logs a warning.
use anyhow::Result;
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::state::SharedState;

pub async fn start(
    _state: SharedState,
    cfg: ghoststrike_common::ListenerConfig,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let pipe = cfg
        .pipe_name
        .clone()
        .unwrap_or_else(|| r"\\.\pipe\ghoststrike".to_string());
    let pipe_display = pipe.clone();

    let handle = tokio::spawn(async move {
        #[cfg(target_os = "windows")]
        {
            smb_server_windows(&pipe, shutdown_rx).await;
        }
        #[cfg(not(target_os = "windows"))]
        {
            warn!(
                "SMB listener requested on non-Windows host (pipe: {pipe}). \
                 This is a stub — run the server on Windows for real SMB support."
            );
            let _ = shutdown_rx.await;
        }
    });

    info!("SMB listener configured for pipe {pipe_display}");
    Ok(handle)
}

#[cfg(target_os = "windows")]
async fn smb_server_windows(pipe: &str, mut shutdown_rx: oneshot::Receiver<()>) {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateNamedPipeW, FILE_FLAG_OVERLAPPED,
        PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(pipe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                255,
                4096,
                4096,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            warn!("CreateNamedPipe failed");
            break;
        }

        // Accept a connection (blocking, simplified).
        unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };

        // TODO: read/write checkin protocol over the pipe in Phase 2.

        if shutdown_rx.try_recv().is_ok() {
            break;
        }
    }
}
