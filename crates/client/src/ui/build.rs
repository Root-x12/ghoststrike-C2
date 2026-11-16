use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10),
            Constraint::Min(4),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[0]);

    draw_form(f, app, top[0]);
    draw_help(f, app, top[1]);
    draw_log(f, app, chunks[1]);
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let bc = &app.build_config;

    let listeners: Vec<&ghoststrike_common::ListenerConfig> = app.listeners.values().collect();
    let listener_name = listeners
        .get(bc.listener_index)
        .map(|l| format!("{} ({}:{})", l.name, l.host, l.port))
        .unwrap_or_else(|| "No listeners — start one first (tab 2)".into());

    let formats = ["EXE", "Shellcode", "DLL"];
    let format_name = formats[bc.format_index % formats.len()];

    let fields: &[(&str, &str, usize)] = &[
        ("Listener",    &listener_name, 0),
        ("Sleep (ms)",  &bc.sleep_ms,    1),
        ("Jitter (%)",  &bc.jitter_pct,  2),
        ("Format",      format_name,     3),
        ("Output path", &bc.output_path, 4),
    ];

    let items: Vec<ListItem> = fields
        .iter()
        .map(|(label, value, idx)| {
            let focused = bc.focused_field == *idx;
            let (label_col, val_col, arrow) = if focused {
                (CYAN, Color::White, "▶ ")
            } else {
                (GRAY, LGRAY, "  ")
            };
            let hint = if focused && (*idx == 0 || *idx == 3) { "  ←→ cycle" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled(arrow, Style::default().fg(RED)),
                Span::styled(format!("{:<14}", label), Style::default().fg(label_col)),
                Span::styled(format!("{:<30}", value), Style::default().fg(val_col).add_modifier(
                    if focused { Modifier::BOLD | Modifier::UNDERLINED } else { Modifier::empty() }
                )),
                Span::styled(hint, Style::default().fg(GRAY)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Line::from(vec![
                    Span::styled(" Payload Builder ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled("↑↓ navigate  ←→ cycle  Enter generate ", Style::default().fg(GRAY)),
                ])),
        );
    f.render_widget(list, area);
}

fn draw_help(f: &mut Frame, _app: &App, area: Rect) {
    let check = Span::styled("  ✓ ", Style::default().fg(GREEN));
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Phase 3 — Evasion",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![check.clone(), Span::styled("ECDH x25519 key exchange", Style::default().fg(LGRAY))]),
        Line::from(vec![check.clone(), Span::styled("Per-build AES-256-GCM key", Style::default().fg(LGRAY))]),
        Line::from(vec![check.clone(), Span::styled("Shellcode / DLL formats", Style::default().fg(LGRAY))]),
        Line::from(vec![check.clone(), Span::styled("SMB named-pipe transport", Style::default().fg(LGRAY))]),
        Line::from(""),
        Line::from(Span::styled(
            "  Agent Obfuscation",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![check.clone(), Span::styled("Indirect syscalls (HWBP)", Style::default().fg(LGRAY))]),
        Line::from(vec![check.clone(), Span::styled("HWBP AMSI/ETW bypass", Style::default().fg(LGRAY))]),
        Line::from(vec![check.clone(), Span::styled("Rich header zeroed", Style::default().fg(LGRAY))]),
        Line::from(vec![check,         Span::styled("Randomised section names", Style::default().fg(LGRAY))]),
    ];

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(" Features ", Style::default().fg(GRAY))),
        );
    f.render_widget(p, area);
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.build_log
        .iter()
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .rev()
        .map(|l| {
            let style = if l.starts_with("[+]") {
                Style::default().fg(GREEN)
            } else if l.starts_with("[!]") {
                Style::default().fg(RED)
            } else if l.starts_with("[*]") {
                Style::default().fg(ORANGE)
            } else {
                Style::default().fg(LGRAY)
            };
            ListItem::new(format!("  {}", l)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(" Build Log ", Style::default().fg(CYAN))),
        );
    f.render_widget(list, area);
}
