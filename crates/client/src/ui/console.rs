use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::{App, InputMode};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Task output log
    let agent_id_str = app
        .selected_agent
        .map(|id| id.to_string()[..8].to_string())
        .unwrap_or_else(|| "none".into());

    let items: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(chunks[0].height as usize - 2)
        .rev()
        .map(|l| {
            let style = if l.starts_with('>') {
                Style::default().fg(Color::Cyan)
            } else if l.starts_with("[!]") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(l.as_str()).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Console — Agent: {agent_id_str} ")),
    );
    f.render_widget(list, chunks[0]);

    // Input box
    let (title, border_color) = match app.input_mode {
        InputMode::Insert => (
            " Command (Esc to exit) ",
            Color::Yellow,
        ),
        InputMode::Normal => (
            " Command ([i] to type) ",
            Color::DarkGray,
        ),
    };

    let input = Paragraph::new(app.console_input.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(title),
        );
    f.render_widget(input, chunks[1]);

    // Cursor
    if app.input_mode == InputMode::Insert {
        f.set_cursor_position((
            chunks[1].x + app.console_input.len() as u16 + 1,
            chunks[1].y + 1,
        ));
    }
}
