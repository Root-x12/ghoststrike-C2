use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "ID", "Hostname", "User", "OS", "Arch", "PID", "Elevated", "Sleep", "Last Seen",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows: Vec<Row> = app
        .agents
        .values()
        .map(|a| {
            let selected = app.selected_agent == Some(a.id);
            let elev_style = if a.elevated {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };
            Row::new(vec![
                Cell::from(a.id.to_string()[..8].to_string()),
                Cell::from(a.hostname.clone()),
                Cell::from(a.username.clone()),
                Cell::from(a.os_version.clone()),
                Cell::from(a.arch.clone()),
                Cell::from(a.pid.to_string()),
                Cell::from(if a.elevated { "YES" } else { "no" }).style(elev_style),
                Cell::from(format!("{}ms", a.sleep_ms)),
                Cell::from(a.last_seen.format("%H:%M:%S").to_string()),
            ])
            .style(if selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            })
        })
        .collect();

    use ratatui::layout::Constraint;
    let widths = [
        Constraint::Length(10),
        Constraint::Length(18),
        Constraint::Length(14),
        Constraint::Length(20),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Agents ({}) — ↑↓ select  Enter → console ",
                    app.agents.len()
                )),
        )
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD));

    let mut state = TableState::default();
    if let Some(sel) = app.selected_agent {
        let idx = app.agents.keys().position(|id| *id == sel);
        state.select(idx);
    }
    f.render_stateful_widget(table, area, &mut state);
}
