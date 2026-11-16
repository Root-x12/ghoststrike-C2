use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;
use crossterm::event::KeyEvent;

use ghoststrike_common::{AgentInfo, ListenerConfig, Task, OperatorMsg, BuildConfig};

#[derive(Debug, Clone)]
pub enum Event {
    Key(KeyEvent),
    Server(OperatorMsg),
    Quit,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Listeners,
    Agents,
    Console,
    Build,
}

impl Tab {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Listeners => "Listeners",
            Self::Agents    => "Agents",
            Self::Console   => "Console",
            Self::Build     => "Build",
        }
    }

    pub fn all() -> &'static [Tab] {
        &[
            Tab::Dashboard,
            Tab::Listeners,
            Tab::Agents,
            Tab::Console,
            Tab::Build,
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Insert,
}

pub struct App {
    pub tab:        Tab,
    pub agents:     HashMap<Uuid, AgentInfo>,
    pub listeners:  HashMap<Uuid, ListenerConfig>,
    pub tasks:      Vec<Task>,
    pub log:        Vec<String>,
    pub selected_agent: Option<Uuid>,
    pub console_input:  String,
    pub input_mode:     InputMode,
    pub build_config:   BuildConfigDraft,
    pub status_msg:     Option<String>,
    pub connected:      bool,
    pub server_name:    String,
    pub operators:      Vec<String>,
    event_tx:           mpsc::Sender<Event>,
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
            tab:            Tab::Dashboard,
            agents:         HashMap::new(),
            listeners:      HashMap::new(),
            tasks:          Vec::new(),
            log:            Vec::new(),
            selected_agent: None,
            console_input:  String::new(),
            input_mode:     InputMode::Normal,
            build_config:   BuildConfigDraft {
                sleep_ms:   "5000".into(),
                jitter_pct: "10".into(),
                output_path: "./payload.exe".into(),
                ..Default::default()
            },
            status_msg:     None,
            connected:      false,
            server_name:    "GhostStrike C2".into(),
            operators:      Vec::new(),
            event_tx,
        }
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        let entry = msg.into();
        if self.log.len() > 500 {
            self.log.remove(0);
        }
        self.log.push(entry);
    }

    pub async fn next_event(
        &self,
        fut: impl std::future::Future<Output = Option<Event>>,
    ) -> Option<Event> {
        fut.await
    }

    pub async fn handle(&mut self, event: Event) {
        use crossterm::event::{KeyCode, KeyModifiers};

        match event {
            Event::Server(msg) => self.handle_server_msg(msg),

            Event::Key(key) => {
                // Global: q quits in Normal mode
                if self.input_mode == InputMode::Normal {
                    match key.code {
                        KeyCode::Char('q') => {
                            let _ = self.event_tx.send(Event::Quit).await;
                        }
                        KeyCode::Char('1') => self.tab = Tab::Dashboard,
                        KeyCode::Char('2') => self.tab = Tab::Listeners,
                        KeyCode::Char('3') => self.tab = Tab::Agents,
                        KeyCode::Char('4') => self.tab = Tab::Console,
                        KeyCode::Char('5') => self.tab = Tab::Build,
                        KeyCode::Tab => self.cycle_tab(false),
                        KeyCode::BackTab => self.cycle_tab(true),
                        KeyCode::Char('i') => self.input_mode = InputMode::Insert,
                        _ => self.handle_tab_key(key),
                    }
                } else {
                    // Insert mode
                    match key.code {
                        KeyCode::Esc => self.input_mode = InputMode::Normal,
                        KeyCode::Enter => self.submit_input().await,
                        KeyCode::Char(c) => {
                            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                                self.input_mode = InputMode::Normal;
                            } else {
                                self.console_input.push(c);
                            }
                        }
                        KeyCode::Backspace => { self.console_input.pop(); }
                        _ => {}
                    }
                }
            }

            Event::Quit => {}
        }
    }

    fn handle_server_msg(&mut self, msg: OperatorMsg) {
        match msg {
            OperatorMsg::AuthOk { server_name, .. } => {
                self.connected   = true;
                self.server_name = server_name;
                self.push_log("Authenticated to server");
            }
            OperatorMsg::AuthFail { reason } => {
                self.push_log(format!("Auth failed: {reason}"));
            }
            OperatorMsg::AgentCheckin { agent } => {
                self.push_log(format!(
                    "[+] Agent {} ({} @ {})",
                    &agent.id.to_string()[..8],
                    agent.username,
                    agent.hostname
                ));
                self.agents.insert(agent.id, agent);
            }
            OperatorMsg::AgentList { agents } => {
                for a in agents {
                    self.agents.insert(a.id, a);
                }
            }
            OperatorMsg::ListenerStarted { config } => {
                self.push_log(format!(
                    "[+] Listener '{}' ({}) started on {}:{}",
                    config.name, config.protocol, config.host, config.port
                ));
                self.listeners.insert(config.id, config);
            }
            OperatorMsg::ListenerStopped { id } => {
                self.listeners.remove(&id);
                self.push_log(format!("[-] Listener {id} stopped"));
            }
            OperatorMsg::ListenerList { listeners } => {
                for l in listeners {
                    self.listeners.insert(l.id, l);
                }
            }
            OperatorMsg::TaskResult { task } => {
                self.push_log(format!(
                    "[Task {}] {}",
                    &task.id.to_string()[..8],
                    task.output.as_deref().unwrap_or("(no output)")
                ));
                self.tasks.push(task);
            }
            OperatorMsg::OperatorJoined { name } => {
                self.push_log(format!("[*] Operator joined: {name}"));
                self.operators.push(name);
            }
            OperatorMsg::OperatorLeft { name } => {
                self.push_log(format!("[*] Operator left: {name}"));
                self.operators.retain(|n| n != &name);
            }
            OperatorMsg::Error { message } => {
                self.push_log(format!("[!] Server error: {message}"));
            }
            _ => {}
        }
    }

    fn handle_tab_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match &self.tab {
            Tab::Agents => {
                match key.code {
                    KeyCode::Up   => self.select_prev_agent(),
                    KeyCode::Down => self.select_next_agent(),
                    KeyCode::Enter => { self.tab = Tab::Console; }
                    _ => {}
                }
            }
            Tab::Listeners => {
                // 'n' = new listener (starts input flow)
            }
            _ => {}
        }
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

    async fn submit_input(&mut self) {
        let input = self.console_input.trim().to_string();
        if input.is_empty() { return; }
        self.console_input.clear();
        self.input_mode = InputMode::Normal;

        if let Some(agent_id) = self.selected_agent {
            use ghoststrike_common::{Task, TaskCommand, TaskStatus};
            use chrono::Utc;

            let task = Task {
                id:           uuid::Uuid::new_v4(),
                agent_id,
                operator:     "operator".into(),
                command:      TaskCommand::Shell { cmd: input.clone() },
                status:       TaskStatus::Pending,
                output:       None,
                created_at:   Utc::now(),
                completed_at: None,
            };
            let msg = OperatorMsg::TaskAgent { task };
            let _ = self.event_tx.send(Event::Server(msg)).await;
            self.push_log(format!("> {input}"));
        } else {
            self.push_log("[!] No agent selected");
        }
    }
}
