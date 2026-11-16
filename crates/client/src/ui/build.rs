use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    draw_form(f, app, chunks[0]);
    draw_help(f, app, chunks[1]);
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let bc = &app.build_config;

    let listeners: Vec<&ghoststrike_common::ListenerConfig> = app.listeners.values().collect();
    let listener_name = listeners
        .get(bc.listener_index)
        .map(|l| format!("{} ({}:{})", l.name, l.host, l.port))
        .unwrap_or_else(|| "No listeners".into());

    let formats = ["EXE", "Shellcode", "DLL"];
    let format_name = formats[bc.format_index % formats.len()];

    let fields = vec![
        ("Listener",    listener_name.as_str(),   0),
        ("Sleep (ms)",  bc.sleep_ms.as_str(),      1),
        ("Jitter (%)",  bc.jitter_pct.as_str(),    2),
        ("Format",      format_name,               3),
        ("Output path", bc.output_path.as_str(),   4),
    ];

    let items: Vec<ListItem> = fields
        .iter()
        .map(|(label, value, idx)| {
            let focused = bc.focused_field == *idx;
            let style = if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!("  {:<15} {}", label, value)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Payload Builder — [Enter] Generate "),
        );
    f.render_widget(list, area);
}

fn draw_help(f: &mut Frame, _app: &App, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Build Features",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  ✓ Per-build AES-256-GCM key"),
        Line::from("  ✓ Encrypted config blob"),
        Line::from("  ✓ Randomised section names"),
        Line::from("  ✓ Compile-time string XOR"),
        Line::from("  ✓ No static signatures"),
        Line::from(""),
        Line::from(Span::styled(
            "  Agent Evasion",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  ✓ Indirect syscalls"),
        Line::from("    (SSN via ntdll walk)"),
        Line::from("  ✓ HWBP VEH engine"),
        Line::from("    (AMSI/ETW bypass)"),
        Line::from(""),
        Line::from(Span::styled(
            "  Keybindings",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("  ↑↓    Select field"),
        Line::from("  ←→    Cycle options"),
        Line::from("  i     Edit value"),
        Line::from("  Enter Generate"),
    ];

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Info "));
    f.render_widget(p, area);
}
