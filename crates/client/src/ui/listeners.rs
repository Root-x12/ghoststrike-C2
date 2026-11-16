use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use crate::app::App;
use super::{RED, GREEN, CYAN, GRAY, LGRAY, ORANGE};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("  #").style(Style::default().fg(RED).add_modifier(Modifier::BOLD)),
        Cell::from("NAME").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("PROTOCOL").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("BIND ADDRESS").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("PORT").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("STATUS").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("SESSIONS").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
        Cell::from("ID").style(Style::default().fg(GRAY).add_modifier(Modifier::BOLD)),
    ]).height(1).bottom_margin(0);

    let listeners: Vec<&ghoststrike_common::ListenerConfig> = app.listeners.values().collect();

    let rows: Vec<Row> = listeners.iter().enumerate().map(|(i, l)| {
        let selected = app.selected_listener == Some(l.id);
        let (status_str, status_col) = if l.active {
            ("● ACTIVE ", GREEN)
        } else {
            ("○ STOPPED", GRAY)
        };
        let protocol_col = match l.protocol {
            ghoststrike_common::ListenerProtocol::Https => CYAN,
            ghoststrike_common::ListenerProtocol::Http  => LGRAY,
            ghoststrike_common::ListenerProtocol::Dns   => ORANGE,
            ghoststrike_common::ListenerProtocol::Smb   => Color::Rgb(180, 100, 220),
        };
        let session_count = app.agents.values()
            .filter(|a| a.listener_id == l.id)
            .count();

        let row_style = if selected {
            Style::default().bg(Color::Rgb(40, 10, 10))
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(format!("  {}", i + 1)).style(Style::default().fg(RED)),
            Cell::from(l.name.clone()).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{}", l.protocol)).style(Style::default().fg(protocol_col)),
            Cell::from(l.host.clone()).style(Style::default().fg(LGRAY)),
            Cell::from(l.port.to_string()).style(Style::default().fg(LGRAY)),
            Cell::from(status_str).style(Style::default().fg(status_col).add_modifier(Modifier::BOLD)),
            Cell::from(if session_count > 0 { format!("{}", session_count) } else { "—".into() })
                .style(Style::default().fg(if session_count > 0 { GREEN } else { GRAY })),
            Cell::from(l.id.to_string()[..8].to_string()).style(Style::default().fg(GRAY)),
        ]).style(row_style)
    }).collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(70, 20, 20)))
                .title(Line::from(vec![
                    Span::styled(" Listeners ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("({}) ", listeners.len()),
                        Style::default().fg(if listeners.is_empty() { GRAY } else { GREEN }),
                    ),
                    Span::styled(
                        "[n] New  [d] Delete  ↑↓ select ",
                        Style::default().fg(GRAY),
                    ),
                ])),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(50, 10, 10))
                .add_modifier(Modifier::BOLD),
        );

    let mut state = TableState::default();
    if let Some(sel) = app.selected_listener {
        state.select(listeners.iter().position(|l| l.id == sel));
    }
    f.render_stateful_widget(table, area, &mut state);
}
