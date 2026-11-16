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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);

    draw_table(f, app, chunks[0]);
    draw_output_preview(f, app, chunks[1]);
}

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("  TIME").style(Style::default().fg(RED).add_modifier(Modifier::BOLD)),
        Cell::from("SESSION").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("HOSTNAME").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("COMMAND").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("OUTPUT (preview)").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
    ]).height(1).bottom_margin(0);

    let visible = area.height.saturating_sub(3) as usize;
    let total   = app.loot.len();
    let start   = if total > visible + app.loot_scroll {
        total - visible - app.loot_scroll
    } else {
        0
    };

    let rows: Vec<Row> = app.loot[start..]
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let selected = app.loot_scroll == app.loot.len().saturating_sub(start + i + 1);
            let time     = entry.timestamp.format("%H:%M:%S").to_string();
            let preview  = entry.output.lines().next().unwrap_or("").trim();
            let preview  = if preview.len() > 50 {
                format!("{}…", &preview[..50])
            } else {
                preview.to_string()
            };
            let cmd_col = if entry.command.contains("Shell") || entry.command.contains("Cmd") {
                ORANGE
            } else {
                CYAN
            };
            let row_style = if selected {
                Style::default().bg(Color::Rgb(40, 10, 10))
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(format!("  {time}")).style(Style::default().fg(GRAY)),
                Cell::from(entry.agent_id.to_string()[..8].to_string())
                    .style(Style::default().fg(RED)),
                Cell::from(entry.hostname.clone())
                    .style(Style::default().fg(Color::White)),
                Cell::from(short_cmd(&entry.command))
                    .style(Style::default().fg(cmd_col)),
                Cell::from(preview)
                    .style(Style::default().fg(LGRAY)),
            ]).style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Line::from(vec![
                    Span::styled(" Loot ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("({} results) ", app.loot.len()),
                        Style::default().fg(if app.loot.is_empty() { GRAY } else { ORANGE }),
                    ),
                    Span::styled("↑↓ scroll ", Style::default().fg(GRAY)),
                ])),
        );

    let mut state = TableState::default();
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_output_preview(f: &mut Frame, app: &App, area: Rect) {
    let entry = app.loot.get(
        app.loot.len().saturating_sub(1 + app.loot_scroll)
    );

    let (title, lines): (String, Vec<Line>) = match entry {
        Some(e) => {
            let title = format!(
                " {} @ {} — {} ",
                e.agent_id.to_string()[..8].to_string(),
                e.hostname,
                short_cmd(&e.command)
            );
            let lines = e.output
                .lines()
                .take(area.height.saturating_sub(2) as usize)
                .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(Color::White))))
                .collect();
            (title, lines)
        }
        None => (
            " Output Preview ".into(),
            vec![Line::from(Span::styled(
                "  No results yet — task an agent in Sessions [3]",
                Style::default().fg(GRAY),
            ))],
        ),
    };

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(60, 60, 60)))
                .title(Span::styled(title, Style::default().fg(CYAN))),
        );
    f.render_widget(p, area);
}

fn short_cmd(cmd: &str) -> &str {
    if cmd.contains("Shell")    { "shell" }
    else if cmd.contains("Ps")  { "ps" }
    else if cmd.contains("Who") { "whoami" }
    else if cmd.contains("Ls")  { "ls" }
    else if cmd.contains("Cat") { "cat" }
    else if cmd.contains("Dl") || cmd.contains("Download") { "download" }
    else if cmd.contains("Inject") { "inject" }
    else if cmd.contains("Hol")    { "hollow" }
    else if cmd.contains("Mig")    { "migrate" }
    else if cmd.contains("Pwd")    { "pwd" }
    else { &cmd[..cmd.len().min(12)] }
}
