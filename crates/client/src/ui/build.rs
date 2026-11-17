use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

// Field indices
const F_LISTENER:   usize = 0;
const F_SLEEP:      usize = 1;
const F_JITTER:     usize = 2;
const F_FORMAT:     usize = 3;
const F_SLEEP_OBF:  usize = 4;
const F_INJECT:     usize = 5;
const F_SANDBOX:    usize = 6;
const F_STACK:      usize = 7;
const F_BLOCK_DLLS: usize = 8;
const F_OUTPUT:     usize = 9;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let top_bottom = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(14), Constraint::Length(10)])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top_bottom[0]);

    draw_basic_config(f, app, cols[0]);
    draw_evasion_config(f, app, cols[1]);
    draw_log(f, app, top_bottom[1]);
}

fn draw_basic_config(f: &mut Frame, app: &App, area: Rect) {
    let bc = &app.build_config;
    let listeners: Vec<&ghoststrike_common::ListenerConfig> = app.listeners.values().collect();
    let listener_name = listeners
        .get(bc.listener_index)
        .map(|l| format!("{} ({}:{})", l.name, l.host, l.port))
        .unwrap_or_else(|| "No listeners — start one first (tab 2)".into());

    let formats = ["EXE", "Shellcode", "DLL"];
    let format_name = formats[bc.format_index % formats.len()];

    let fields: &[(&str, &str, usize, bool)] = &[
        ("Listener",    &listener_name, F_LISTENER, true),
        ("Sleep (ms)",  &bc.sleep_ms,   F_SLEEP,    false),
        ("Jitter (%)",  &bc.jitter_pct, F_JITTER,   false),
        ("Format",      format_name,    F_FORMAT,   true),
        ("Output path", &bc.output_path, F_OUTPUT,  false),
    ];

    let items: Vec<ListItem> = fields.iter().map(|(label, value, idx, is_cycle)| {
        let focused = bc.focused_field == *idx;
        let (label_col, val_col, arrow) = if focused {
            (CYAN, Color::White, "▶ ")
        } else {
            (GRAY, LGRAY, "  ")
        };
        let hint = match (focused, is_cycle) {
            (true, true)  => "  ←→ cycle",
            (true, false) => "  i to edit",
            _             => "",
        };
        ListItem::new(Line::from(vec![
            Span::styled(arrow, Style::default().fg(RED)),
            Span::styled(format!("{:<14}", label), Style::default().fg(label_col)),
            Span::styled(
                format!("{:<24}", value),
                Style::default().fg(val_col).add_modifier(
                    if focused { Modifier::BOLD | Modifier::UNDERLINED } else { Modifier::empty() }
                ),
            ),
            Span::styled(hint, Style::default().fg(GRAY)),
        ]))
    }).collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Line::from(vec![
                    Span::styled(" Payload Config ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled("↑↓ navigate  ←→ cycle  Enter generate ", Style::default().fg(GRAY)),
                ])),
        );
    f.render_widget(list, area);
}

fn draw_evasion_config(f: &mut Frame, app: &App, area: Rect) {
    let bc = &app.build_config;

    let sleep_obf_opts = ["None", "Ekko", "NtDelayExec"];
    let inject_opts    = ["CreateThread", "NtCreateThreadEx", "QueueUserAPC"];
    let sleep_obf = sleep_obf_opts[bc.sleep_obf_index % sleep_obf_opts.len()];
    let inject    = inject_opts[bc.inject_index % inject_opts.len()];

    let toggle_str = |on: bool| if on { "✓ ENABLED" } else { "✗ disabled" };
    let toggle_col = |on: bool| if on { GREEN } else { GRAY };

    // Cycle fields
    let cycle_fields: &[(&str, &str, usize)] = &[
        ("Sleep Obfuscation", sleep_obf,         F_SLEEP_OBF),
        ("Injection Method",  inject,             F_INJECT),
    ];
    // Toggle fields
    let toggle_fields: &[(&str, bool, usize)] = &[
        ("Sandbox Evasion",   bc.sandbox_evasion, F_SANDBOX),
        ("Stack Spoof",       bc.stack_spoof,     F_STACK),
        ("Block Non-MS DLLs", bc.block_dlls,      F_BLOCK_DLLS),
    ];

    let mut items: Vec<ListItem> = Vec::new();

    // Section header
    items.push(ListItem::new(Line::from(
        Span::styled("  Obfuscation", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD))
    )));

    for (label, value, idx) in cycle_fields {
        let focused = bc.focused_field == *idx;
        let (lc, vc, arrow) = if focused { (CYAN, Color::White, "▶ ") } else { (GRAY, LGRAY, "  ") };
        let hint = if focused { "  ←→" } else { "" };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(arrow, Style::default().fg(RED)),
            Span::styled(format!("{:<20}", label), Style::default().fg(lc)),
            Span::styled(
                format!("{:<18}", value),
                Style::default().fg(vc).add_modifier(if focused { Modifier::BOLD | Modifier::UNDERLINED } else { Modifier::empty() })
            ),
            Span::styled(hint, Style::default().fg(GRAY)),
        ])));
    }

    items.push(ListItem::new(Line::from("")));
    items.push(ListItem::new(Line::from(
        Span::styled("  Detection Evasion", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD))
    )));

    for (label, on, idx) in toggle_fields {
        let focused = bc.focused_field == *idx;
        let (lc, arrow) = if focused { (CYAN, "▶ ") } else { (GRAY, "  ") };
        let hint = if focused { "  Space/Enter toggle" } else { "" };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(arrow, Style::default().fg(RED)),
            Span::styled(format!("{:<20}", label), Style::default().fg(lc)),
            Span::styled(
                format!("{:<12}", toggle_str(*on)),
                Style::default().fg(toggle_col(*on)).add_modifier(Modifier::BOLD),
            ),
            Span::styled(hint, Style::default().fg(GRAY)),
        ])));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 40, 10)))
                .title(Span::styled(" Evasion Options ", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD))),
        );
    f.render_widget(list, area);
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
