use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

use crate::app::{App, PopupKind};
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + r.width.saturating_sub(width) / 2;
    let y = r.y + r.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width:  width.min(r.width),
        height: height.min(r.height),
    }
}

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match app.popup.as_ref().unwrap() {
        PopupKind::AgentActions => draw_agent_actions(f, app, area),
        PopupKind::NewListener  => draw_new_listener(f, app, area),
        PopupKind::AgentInfo    => draw_agent_info(f, app, area),
        PopupKind::Confirm { msg } => draw_confirm(f, msg, area),
    }
}

fn draw_agent_actions(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(44, 16, area);
    f.render_widget(Clear, popup);

    let agent = app.selected_agent.and_then(|id| app.agents.get(&id));
    let title = match agent {
        Some(a) => format!(
            " {} @ {} ",
            &a.id.to_string()[..8], a.hostname
        ),
        None => " Agent Actions ".into(),
    };

    let items = vec![
        ListItem::new(Line::from(vec![
            Span::styled("  [i]  ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Interact   ", Style::default().fg(Color::White)),
            Span::styled("Open interactive console", Style::default().fg(GRAY)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  [p]  ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Process list   ", Style::default().fg(Color::White)),
            Span::styled("Run ps", Style::default().fg(GRAY)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  [w]  ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
            Span::styled("Whoami         ", Style::default().fg(Color::White)),
            Span::styled("Run whoami", Style::default().fg(GRAY)),
        ])),
        ListItem::new(Line::from("")),
        ListItem::new(Line::from(vec![
            Span::styled("  [k]  ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
            Span::styled("Kill agent     ", Style::default().fg(Color::Rgb(255, 100, 100))),
            Span::styled("Terminate (confirm)", Style::default().fg(GRAY)),
        ])),
        ListItem::new(Line::from("")),
        ListItem::new(Line::from(vec![
            Span::styled("  [I]  ", Style::default().fg(LGRAY).add_modifier(Modifier::BOLD)),
            Span::styled("Agent info     ", Style::default().fg(LGRAY)),
            Span::styled("Full detail view", Style::default().fg(GRAY)),
        ])),
        ListItem::new(Line::from("")),
        ListItem::new(Line::from(vec![
            Span::styled("  [Esc]  ", Style::default().fg(GRAY)),
            Span::styled("Close", Style::default().fg(GRAY)),
        ])),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .title(Span::styled(title, Style::default().fg(RED).add_modifier(Modifier::BOLD))),
        );
    f.render_widget(list, popup);
}

fn draw_new_listener(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(52, 14, area);
    f.render_widget(Clear, popup);

    let d = &app.listener_draft;
    let protos = ["HTTP", "HTTPS", "DNS", "SMB"];
    let proto  = protos[d.protocol_index % protos.len()];

    let fields = [
        ("Name    ", d.name.as_str(),  false, 0),
        ("Protocol", proto,             true,  1),
        ("Host    ", d.host.as_str(),  false, 2),
        ("Port    ", d.port.as_str(),  false, 3),
    ];

    let items: Vec<ListItem> = fields.iter().map(|(label, value, is_cycle, idx)| {
        let focused = d.focused_field == *idx;
        let (label_col, val_col, border) = if focused {
            (CYAN, Color::White, "▶ ")
        } else {
            (GRAY, LGRAY, "  ")
        };
        let hint = if focused && *is_cycle { " ← → cycle" } else { "" };
        ListItem::new(Line::from(vec![
            Span::styled(border, Style::default().fg(RED)),
            Span::styled(format!("{:<10}", label), Style::default().fg(label_col)),
            Span::styled(format!("{:<20}", value), Style::default().fg(val_col).add_modifier(
                if focused { Modifier::BOLD | Modifier::UNDERLINED } else { Modifier::empty() }
            )),
            Span::styled(hint, Style::default().fg(GRAY)),
        ]))
    }).collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CYAN))
                .title(Line::from(vec![
                    Span::styled(" New Listener ", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
                    Span::styled("↑↓ navigate  Enter start  Esc cancel ", Style::default().fg(GRAY)),
                ])),
        );
    f.render_widget(list, popup);
}

fn draw_agent_info(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(60, 18, area);
    f.render_widget(Clear, popup);

    let agent = match app.selected_agent.and_then(|id| app.agents.get(&id)) {
        Some(a) => a,
        None    => return,
    };

    let priv_col = if agent.elevated { RED } else { GREEN };
    let priv_str = if agent.elevated { "SYSTEM / High Integrity" } else { "Medium Integrity" };
    let listener = app.listeners.get(&agent.listener_id)
        .map(|l| format!("{} {} {}:{}", l.name, l.protocol, l.host, l.port))
        .unwrap_or_else(|| "unknown".into());

    let id_str    = agent.id.to_string();
    let pid_str   = agent.pid.to_string();
    let sleep_str = format!("{}ms / {}% jitter", agent.sleep_ms, agent.jitter_pct);
    let lines = vec![
        Line::from(""),
        kv("  Session ID  ", &id_str),
        kv("  Build ID    ", &agent.build_id),
        Line::from(""),
        kv("  Hostname    ", &agent.hostname),
        kv("  Username    ", &agent.username),
        Line::from(vec![
            Span::styled("  Integrity   ", Style::default().fg(GRAY)),
            Span::styled(priv_str, Style::default().fg(priv_col).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        kv("  OS Version  ", &agent.os_version),
        kv("  Arch        ", &agent.arch),
        kv("  PID         ", &pid_str),
        Line::from(""),
        kv("  Listener    ", &listener),
        kv("  Sleep       ", &sleep_str),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(GRAY),
        )),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CYAN))
                .title(Span::styled(
                    format!(" Session Info: {} ", &agent.id.to_string()[..8]),
                    Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(p, popup);
}

fn draw_confirm(f: &mut Frame, msg: &str, area: Rect) {
    let popup = centered_rect(50, 7, area);
    f.render_widget(Clear, popup);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", msg),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [y] / Enter  ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
            Span::styled("Confirm    ", Style::default().fg(Color::White)),
            Span::styled("[any other]  Cancel", Style::default().fg(GRAY)),
        ]),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(RED))
                .title(Span::styled(
                    " Confirm ",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(p, popup);
}

fn kv<'a>(key: &'a str, val: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(key, Style::default().fg(GRAY)),
        Span::styled(val, Style::default().fg(Color::White)),
    ])
}
