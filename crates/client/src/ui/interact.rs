use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use chrono::Utc;

use crate::app::{App, InputMode};
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let agent = app.selected_agent.and_then(|id| app.agents.get(&id));

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(32)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(chunks[0]);

    draw_output(f, app, left[0]);
    draw_input(f, app, left[1]);
    draw_agent_panel(f, app, agent, chunks[1]);
}

fn draw_output(f: &mut Frame, app: &App, area: Rect) {
    let agent_label = match app.selected_agent.and_then(|id| app.agents.get(&id)) {
        Some(a) => format!(
            " {} @ {} — {} ",
            a.username, a.hostname, &a.id.to_string()[..8]
        ),
        None => " No session selected — go to Sessions [3] ".into(),
    };

    let visible = area.height.saturating_sub(2) as usize;
    let total   = app.log.len();
    let start   = if total > visible + app.log_scroll {
        total - visible - app.log_scroll
    } else {
        0
    };
    let end = (start + visible).min(total);

    let items: Vec<ListItem> = app.log[start..end]
        .iter()
        .map(|(ts, l)| {
            let time = ts.format("%H:%M:%S").to_string();
            let (style, prefix) = if l.starts_with("> ") {
                (Style::default().fg(CYAN), "▶")
            } else if l.starts_with("[+]") || l.starts_with("[>]") {
                (Style::default().fg(GREEN), "")
            } else if l.starts_with("[!]") {
                (Style::default().fg(Color::Rgb(255, 80, 80)), "")
            } else if l.starts_with("[*]") {
                (Style::default().fg(LGRAY), "")
            } else {
                (Style::default().fg(Color::White), "")
            };
            let _ = prefix;
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {time} "), Style::default().fg(GRAY)),
                Span::styled(l.as_str(), style),
            ]))
        })
        .collect();

    let scroll_hint = if app.log_scroll > 0 {
        format!(" (↑{} lines scrolled) ", app.log_scroll)
    } else {
        String::new()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Line::from(vec![
                    Span::styled(" Interact", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled(agent_label, Style::default().fg(CYAN)),
                    Span::styled(scroll_hint, Style::default().fg(GRAY)),
                ])),
        );
    f.render_widget(list, area);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let (title, border_col, prompt_col) = match app.input_mode {
        InputMode::Insert => (
            " Command — Esc exit  ↑↓ history ",
            Color::Rgb(200, 150, 0),
            CYAN,
        ),
        InputMode::Normal => (
            " [i] to type ",
            Color::Rgb(50, 50, 50),
            GRAY,
        ),
    };

    let content = Line::from(vec![
        Span::styled("❯ ", Style::default().fg(prompt_col).add_modifier(Modifier::BOLD)),
        Span::styled(app.console_input.as_str(), Style::default().fg(Color::White)),
    ]);

    let input = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_col))
                .title(Span::styled(title, Style::default().fg(border_col))),
        );
    f.render_widget(input, area);

    if app.input_mode == InputMode::Insert {
        f.set_cursor_position((
            area.x + app.console_input.len() as u16 + 3, // 3 = border + "❯ "
            area.y + 1,
        ));
    }
}

fn draw_agent_panel(
    f:     &mut Frame,
    app:   &App,
    agent: Option<&ghoststrike_common::AgentInfo>,
    area:  Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    // ── Agent info ─────────────────────────────────────────────────────────────
    let info_lines = match agent {
        Some(a) => {
            let priv_col = if a.elevated { RED } else { GREEN };
            let priv_str = if a.elevated { "SYSTEM" } else { "User" };
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  ID  ", Style::default().fg(GRAY)),
                ]),
                Line::from(vec![
                    Span::styled(
                        format!("  {} ", &a.id.to_string()[..8]),
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                kv("  Host ", &a.hostname),
                kv("  User ", &a.username),
                Line::from(vec![
                    Span::styled("  Priv ", Style::default().fg(GRAY)),
                    Span::styled(priv_str, Style::default().fg(priv_col).add_modifier(Modifier::BOLD)),
                ]),
                kv("  OS   ", &short_os(&a.os_version)),
                kv("  Arch ", &a.arch),
                {
                    let pid = a.pid.to_string();
                    Line::from(vec![
                        Span::styled("  PID   ", Style::default().fg(GRAY)),
                        Span::styled(pid, Style::default().fg(Color::White)),
                    ])
                },
                Line::from(vec![
                    Span::styled("  Sleep ", Style::default().fg(GRAY)),
                    Span::styled(format!("{}ms", a.sleep_ms), Style::default().fg(LGRAY)),
                ]),
            ]
        }
        None => vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No session",
                Style::default().fg(GRAY),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Select one in",
                Style::default().fg(GRAY),
            )),
            Line::from(Span::styled(
                "  Sessions [3]",
                Style::default().fg(CYAN),
            )),
        ],
    };

    let info = Paragraph::new(info_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(" Agent ", Style::default().fg(RED))),
        );
    f.render_widget(info, chunks[0]);

    // ── Quick reference ────────────────────────────────────────────────────────
    let cmds = vec![
        ("whoami",           "Current user"),
        ("ps",               "Process list"),
        ("ls <path>",        "Directory list"),
        ("cat <path>",       "Read file"),
        ("shell <cmd>",      "Shell command"),
        ("download <path>",  "Download file"),
        ("upload <l> <r>",   "Upload file"),
        ("sleep <ms>",       "Set sleep"),
        ("inject <pid> <h>", "Shellcode"),
        ("migrate <pid>",    "Migrate"),
        ("hollow <path>",    "Hollow"),
        ("kill",             "Terminate"),
    ];

    let cmd_lines: Vec<Line> = cmds.iter().map(|(cmd, desc)| {
        Line::from(vec![
            Span::styled(format!("  {:<18}", cmd), Style::default().fg(CYAN)),
            Span::styled(format!(" {}", desc), Style::default().fg(GRAY)),
        ])
    }).collect();

    let cmd_ref = Paragraph::new(cmd_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(" Commands ", Style::default().fg(GRAY))),
        );
    f.render_widget(cmd_ref, chunks[1]);
}

fn kv<'a>(key: &'a str, val: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(key, Style::default().fg(GRAY)),
        Span::styled(val, Style::default().fg(Color::White)),
    ])
}

fn short_os(os: &str) -> &str {
    if os.contains("Windows 10") { "Win 10" }
    else if os.contains("Windows 11") { "Win 11" }
    else if os.contains("Windows") || os.contains("Win") { "Windows" }
    else if os.contains("Ubuntu") { "Ubuntu" }
    else if os.contains("Linux") || os.contains("linux") { "Linux" }
    else if os.contains("macOS") { "macOS" }
    else { &os[..os.len().min(10)] }
}
