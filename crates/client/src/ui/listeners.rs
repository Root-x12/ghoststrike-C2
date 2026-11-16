use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["ID", "Name", "Protocol", "Host", "Port", "Status"])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .height(1);

    let rows: Vec<Row> = app
        .listeners
        .values()
        .map(|l| {
            let status_style = if l.active {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            Row::new(vec![
                Cell::from(l.id.to_string()[..8].to_string()),
                Cell::from(l.name.clone()),
                Cell::from(format!("{}", l.protocol)),
                Cell::from(l.host.clone()),
                Cell::from(l.port.to_string()),
                Cell::from(if l.active { "ACTIVE" } else { "STOPPED" })
                    .style(status_style),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Length(8),
        Constraint::Length(20),
        Constraint::Length(6),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Listeners — [n]ew [d]elete "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let mut state = TableState::default();
    f.render_stateful_widget(table, area, &mut state);

    // Help hint at bottom
    let help_area = Rect {
        y:      area.y + area.height - 1,
        height: 1,
        ..area
    };
    use ratatui::widgets::Paragraph;
    let hint = Paragraph::new(" [n] New listener  [d] Delete selected  [Enter] Details")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, help_area);
}
