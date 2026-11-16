use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::app::App;
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // Split: main table top, detail panel bottom
    let (table_area, detail_area) = if app.selected_agent.is_some() {
        let c = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(6)])
            .split(area);
        (c[0], Some(c[1]))
    } else {
        (area, None)
    };

    draw_table(f, app, table_area);
    if let Some(da) = detail_area {
        draw_detail(f, app, da);
    }
}

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("  SESSION").style(Style::default().fg(RED).add_modifier(Modifier::BOLD)),
        Cell::from("HOSTNAME").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("USER").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("OS").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("ARCH").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("PID").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("INTEGRITY").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("SLEEP").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("LAST SEEN").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("LISTENER").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
    ]).height(1).bottom_margin(0);

    let agents: Vec<&ghoststrike_common::AgentInfo> = app.agents.values().collect();

    let rows: Vec<Row> = agents.iter().map(|a| {
        let selected  = app.selected_agent == Some(a.id);
        let priv_col  = if a.elevated { RED } else { GREEN };
        let priv_str  = if a.elevated { "SYSTEM  " } else { "Medium  " };
        let dot       = if a.elevated { "⬆" } else { "○" };
        let elapsed   = elapsed_str(a.last_seen);
        let listener  = app.listeners.get(&a.listener_id)
            .map(|l| l.name.as_str())
            .unwrap_or("unknown");

        let row_style = if selected {
            Style::default().bg(Color::Rgb(40, 10, 10)).fg(Color::White)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(Line::from(vec![
                Span::styled(format!(" {} ", dot), Style::default().fg(priv_col)),
                Span::styled(a.id.to_string()[..8].to_string(), Style::default().fg(Color::White)),
            ])),
            Cell::from(a.hostname.clone()).style(Style::default().fg(Color::White)),
            Cell::from(a.username.clone()).style(Style::default().fg(LGRAY)),
            Cell::from(short_os(&a.os_version)).style(Style::default().fg(GRAY)),
            Cell::from(a.arch.clone()).style(Style::default().fg(GRAY)),
            Cell::from(a.pid.to_string()).style(Style::default().fg(GRAY)),
            Cell::from(priv_str).style(Style::default().fg(priv_col).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{}ms", a.sleep_ms)).style(Style::default().fg(GRAY)),
            Cell::from(elapsed).style(Style::default().fg(GRAY)),
            Cell::from(listener).style(Style::default().fg(CYAN)),
        ]).style(row_style)
    }).collect();

    let widths = [
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Line::from(vec![
                    Span::styled(" Sessions ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("({}) ", app.agents.len()),
                        Style::default().fg(if app.agents.is_empty() { GRAY } else { GREEN }),
                    ),
                    Span::styled(
                        "↑↓ select  Enter menu  [i] interact  [p] ps  [w] whoami ",
                        Style::default().fg(GRAY),
                    ),
                ])),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(50, 10, 10))
                .add_modifier(Modifier::BOLD),
        );

    let mut state = TableState::default();
    if let Some(sel) = app.selected_agent {
        state.select(agents.iter().position(|a| a.id == sel));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let agent = match app.selected_agent.and_then(|id| app.agents.get(&id)) {
        Some(a) => a,
        None    => return,
    };

    let priv_col = if agent.elevated { RED } else { GREEN };
    let priv_str = if agent.elevated { "SYSTEM / High" } else { "Medium" };

    let listener_name = app.listeners.get(&agent.listener_id)
        .map(|l| format!("{} ({}:{})", l.name, l.host, l.port))
        .unwrap_or_else(|| agent.listener_id.to_string()[..8].to_string());

    let lines = vec![
        Line::from(vec![
            Span::styled("  ID:      ", Style::default().fg(GRAY)),
            Span::styled(agent.id.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("   Hostname: ", Style::default().fg(GRAY)),
            Span::styled(agent.hostname.clone(), Style::default().fg(Color::White)),
            Span::styled("   User: ", Style::default().fg(GRAY)),
            Span::styled(agent.username.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  OS:      ", Style::default().fg(GRAY)),
            Span::styled(agent.os_version.clone(), Style::default().fg(LGRAY)),
            Span::styled("   Arch: ", Style::default().fg(GRAY)),
            Span::styled(agent.arch.clone(), Style::default().fg(LGRAY)),
            Span::styled("   PID: ", Style::default().fg(GRAY)),
            Span::styled(agent.pid.to_string(), Style::default().fg(LGRAY)),
        ]),
        Line::from(vec![
            Span::styled("  Integrity: ", Style::default().fg(GRAY)),
            Span::styled(priv_str, Style::default().fg(priv_col).add_modifier(Modifier::BOLD)),
            Span::styled("   Sleep: ", Style::default().fg(GRAY)),
            Span::styled(format!("{}ms / {}% jitter", agent.sleep_ms, agent.jitter_pct), Style::default().fg(LGRAY)),
        ]),
        Line::from(vec![
            Span::styled("  Listener: ", Style::default().fg(GRAY)),
            Span::styled(listener_name, Style::default().fg(CYAN)),
            Span::styled("   Build: ", Style::default().fg(GRAY)),
            Span::styled(agent.build_id.chars().take(8).collect::<String>(), Style::default().fg(LGRAY)),
            Span::styled("   Last: ", Style::default().fg(GRAY)),
            Span::styled(elapsed_str(agent.last_seen), Style::default().fg(GRAY)),
        ]),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Span::styled(" Session Detail ", Style::default().fg(RED))),
        );
    f.render_widget(p, area);
}

fn short_os(os: &str) -> &str {
    if os.contains("Windows 10") || os.contains("Win 10") { "Win 10" }
    else if os.contains("Windows 11") { "Win 11" }
    else if os.contains("Windows") || os.contains("Win") { "Windows" }
    else if os.contains("Ubuntu") { "Ubuntu" }
    else if os.contains("Debian") { "Debian" }
    else if os.contains("Linux") || os.contains("linux") { "Linux" }
    else if os.contains("macOS") || os.contains("Darwin") { "macOS" }
    else { &os[..os.len().min(10)] }
}

fn elapsed_str(ts: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (chrono::Utc::now() - ts).num_seconds().max(0);
    if secs < 60      { format!("{}s",   secs) }
    else if secs < 3600 { format!("{}m", secs / 60) }
    else              { format!("{}h",  secs / 3600) }
}
