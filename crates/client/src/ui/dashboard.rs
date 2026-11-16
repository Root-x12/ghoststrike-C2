use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use crate::app::App;
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE, BG_BAR};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let top_bottom = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(10)])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(top_bottom[0]);

    draw_network_map(f, app, top[0]);
    draw_right_panel(f, app, top[1]);
    draw_session_table(f, app, top_bottom[1]);
}

fn draw_network_map(f: &mut Frame, app: &App, area: Rect) {
    let agent_list: Vec<&ghoststrike_common::AgentInfo> = app.agents.values().collect();

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("╔══════════════════════╗", Style::default().fg(RED)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("║  ", Style::default().fg(RED)),
            Span::styled("GhostStrike Server    ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("║", Style::default().fg(RED)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("╚══════════╤═══════════╝", Style::default().fg(RED)),
        ]),
    ];

    if agent_list.is_empty() {
        lines.push(Line::from(vec![
            Span::raw("             "),
            Span::styled("│", Style::default().fg(GRAY)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("         "),
            Span::styled("[ no sessions ]", Style::default().fg(GRAY)),
        ]));
    } else {
        // Show up to 6 agents in tree form
        let show = agent_list.len().min(6);
        lines.push(Line::from(vec![
            Span::raw("             "),
            Span::styled("│", Style::default().fg(GRAY)),
        ]));

        for (i, agent) in agent_list.iter().take(show).enumerate() {
            let is_last  = i == show - 1;
            let priv_col = if agent.elevated { RED } else { GREEN };
            let priv_sym = if agent.elevated { "⬆" } else { "○" };
            let conn     = if is_last { "└──" } else { "├──" };
            let name     = if agent.hostname.len() > 14 {
                format!("{}…", &agent.hostname[..13])
            } else {
                agent.hostname.clone()
            };
            lines.push(Line::from(vec![
                Span::raw("         "),
                Span::styled(conn, Style::default().fg(GRAY)),
                Span::styled(format!("[{}]", priv_sym), Style::default().fg(priv_col)),
                Span::styled(
                    format!(" {:<14} ", name),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{}", &agent.id.to_string()[..6]),
                    Style::default().fg(GRAY),
                ),
            ]));
        }
        if agent_list.len() > 6 {
            lines.push(Line::from(vec![
                Span::raw("         "),
                Span::styled(
                    format!("    … +{} more", agent_list.len() - 6),
                    Style::default().fg(GRAY),
                ),
            ]));
        }
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(" Network Map ", Style::default().fg(RED).add_modifier(Modifier::BOLD))),
        );
    f.render_widget(p, area);
}

fn draw_right_panel(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    // ── Stats bar ──────────────────────────────────────────────────────────────
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let counters = [
        ("SESSIONS",  app.agents.len(),    GREEN),
        ("LISTENERS", app.listeners.len(), CYAN),
        ("OPERATORS", app.operators.len(), Color::Rgb(180, 100, 220)),
        ("TASKS",     app.tasks.len(),     ORANGE),
    ];

    for (i, (label, count, color)) in counters.iter().enumerate() {
        let content = vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("{:^9}", count.to_string()),
                Style::default().fg(*color).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("{:^9}", label),
                Style::default().fg(GRAY),
            )),
        ];
        let p = Paragraph::new(content)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(45, 45, 45))),
            );
        f.render_widget(p, stats_chunks[i]);
    }

    // ── Event log ─────────────────────────────────────────────────────────────
    let visible = chunks[1].height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app.log
        .iter()
        .rev()
        .take(visible)
        .rev()
        .map(|(ts, l)| {
            let time  = ts.format("%H:%M:%S").to_string();
            let (prefix_col, text_col) = if l.starts_with("[+]") || l.starts_with("[>]") {
                (GREEN,  Color::White)
            } else if l.starts_with("[!]") {
                (RED,    Color::Rgb(255, 160, 160))
            } else if l.starts_with("[*]") || l.starts_with(">") {
                (CYAN,   LGRAY)
            } else {
                (GRAY,   LGRAY)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {time} "), Style::default().fg(GRAY)),
                Span::styled(l.as_str(), Style::default().fg(text_col)),
            ]))
            .style(Style::default())
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(
                    " Activity Log ",
                    Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(list, chunks[1]);
}

fn draw_session_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("  ID").style(Style::default().fg(RED).add_modifier(Modifier::BOLD)),
        Cell::from("HOSTNAME").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("USER").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("OS").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("ARCH").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("PRIV").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("SLEEP").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("LAST SEEN").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
    ]).height(1).bottom_margin(0);

    let rows: Vec<Row> = app.agents.values().map(|a| {
        let priv_col = if a.elevated { RED } else { GREEN };
        let priv_str = if a.elevated { "SYSTEM" } else { "USER  " };
        let dot = if a.elevated { "⬆" } else { "○" };
        let elapsed = {
            let secs = (chrono::Utc::now() - a.last_seen).num_seconds();
            if secs < 60      { format!("{}s",    secs) }
            else if secs < 3600 { format!("{}m", secs/60) }
            else              { format!("{}h",  secs/3600) }
        };
        Row::new(vec![
            Cell::from(format!(" {} {}", dot, &a.id.to_string()[..8])).style(Style::default().fg(priv_col)),
            Cell::from(a.hostname.clone()).style(Style::default().fg(Color::White)),
            Cell::from(a.username.clone()).style(Style::default().fg(LGRAY)),
            Cell::from(short_os(&a.os_version)).style(Style::default().fg(GRAY)),
            Cell::from(a.arch.clone()).style(Style::default().fg(GRAY)),
            Cell::from(priv_str).style(Style::default().fg(priv_col).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{}ms", a.sleep_ms)).style(Style::default().fg(GRAY)),
            Cell::from(elapsed).style(Style::default().fg(GRAY)),
        ])
    }).collect();

    let widths = [
        Constraint::Length(14), Constraint::Length(18), Constraint::Length(16),
        Constraint::Length(14), Constraint::Length(6),  Constraint::Length(8),
        Constraint::Length(8),  Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(
                    format!(" Active Sessions ({}) — press [3] to interact ", app.agents.len()),
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(table, area);
}

fn short_os(os: &str) -> String {
    let os = os.to_lowercase();
    if os.contains("windows 10") || os.contains("win 10") { "Win 10".into() }
    else if os.contains("windows 11") { "Win 11".into() }
    else if os.contains("windows") || os.contains("win") { "Windows".into() }
    else if os.contains("ubuntu") { "Ubuntu".into() }
    else if os.contains("debian") { "Debian".into() }
    else if os.contains("linux") { "Linux".into() }
    else if os.contains("macos") || os.contains("darwin") { "macOS".into() }
    else { os.chars().take(10).collect() }
}
