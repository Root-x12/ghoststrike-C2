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
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_event_log(f, app, chunks[0]);
    draw_stats(f, app, chunks[1]);
}

fn draw_event_log(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .rev()
        .map(|l| ListItem::new(l.as_str()))
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Event Log ")
                .title_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}

fn draw_stats(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    // Stats box
    let stats = vec![
        Line::from(vec![
            Span::styled("  Agents:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.agents.len().to_string(),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Listeners: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.listeners.len().to_string(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Operators: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.operators.len().to_string(),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let p = Paragraph::new(stats)
        .block(Block::default().borders(Borders::ALL).title(" Stats "));
    f.render_widget(p, chunks[0]);

    // Active listeners summary
    let items: Vec<ListItem> = app
        .listeners
        .values()
        .map(|l| {
            ListItem::new(format!(
                " [{}] {} — {}:{}",
                if l.active { "+" } else { "-" },
                l.name,
                l.host,
                l.port
            ))
            .style(Style::default().fg(if l.active { Color::Green } else { Color::DarkGray }))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Active Listeners "),
    );
    f.render_widget(list, chunks[1]);
}
