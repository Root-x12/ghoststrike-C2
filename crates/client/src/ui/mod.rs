mod dashboard;
mod listeners;
mod agents;
mod console;
mod build;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Tabs},
    Frame,
};

use crate::app::{App, Tab};

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header / tabs
            Constraint::Min(0),     // main content
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    draw_tabs(f, app, chunks[0]);

    match app.tab {
        Tab::Dashboard => dashboard::draw(f, app, chunks[1]),
        Tab::Listeners => listeners::draw(f, app, chunks[1]),
        Tab::Agents    => agents::draw(f, app, chunks[1]),
        Tab::Console   => console::draw(f, app, chunks[1]),
        Tab::Build     => build::draw(f, app, chunks[1]),
    }

    draw_statusbar(f, app, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::all()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(Span::styled(
                format!(" {} [{}] ", t.title(), i + 1),
                Style::default().fg(Color::White),
            ))
        })
        .collect();

    let selected = Tab::all().iter().position(|t| t == &app.tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " GhostStrike C2 — {} ",
                    app.server_name
                ))
                .title_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        )
        .select(selected)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    use ratatui::widgets::Paragraph;

    let status = if app.connected {
        format!(
            " Connected | Agents: {} | Listeners: {} | [q]uit [Tab]switch [i]nsert",
            app.agents.len(),
            app.listeners.len()
        )
    } else {
        " Connecting to server…".to_string()
    };

    let p = Paragraph::new(status)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(p, area);
}
