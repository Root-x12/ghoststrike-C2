mod dashboard;
mod listeners;
mod sessions;
mod interact;
mod build;
mod loot;
mod popup;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

use crate::app::{App, Tab};

pub(crate) const RED:    Color = Color::Rgb(200, 30,  30);
pub(crate) const ORANGE: Color = Color::Rgb(220, 120, 0);
pub(crate) const GREEN:  Color = Color::Rgb(50,  205, 50);
pub(crate) const CYAN:   Color = Color::Rgb(0,   190, 220);
pub(crate) const GRAY:   Color = Color::Rgb(100, 100, 100);
pub(crate) const LGRAY:  Color = Color::Rgb(170, 170, 170);
pub(crate) const BG_BAR: Color = Color::Rgb(20,  20,  25);
pub(crate) const BG_SEL: Color = Color::Rgb(35,  10,  10);

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // logo bar
            Constraint::Length(2),  // tab bar
            Constraint::Min(0),     // content
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    draw_logo(f, app, chunks[0]);
    draw_tabs(f, app, chunks[1]);

    match app.tab {
        Tab::Dashboard => dashboard::draw(f, app, chunks[2]),
        Tab::Listeners => listeners::draw(f, app, chunks[2]),
        Tab::Sessions  => sessions::draw(f, app, chunks[2]),
        Tab::Interact  => interact::draw(f, app, chunks[2]),
        Tab::Build     => build::draw(f, app, chunks[2]),
        Tab::Loot      => loot::draw(f, app, chunks[2]),
    }

    draw_statusbar(f, app, chunks[3]);

    // Render popup overlay last (on top of everything)
    if app.popup.is_some() {
        popup::draw(f, app, area);
    }
}

fn draw_logo(f: &mut Frame, app: &App, area: Rect) {
    let conn_dot = if app.connected {
        Span::styled("● ", Style::default().fg(GREEN))
    } else {
        Span::styled("● ", Style::default().fg(RED))
    };

    let title = Span::styled(
        "GHOSTSTRIKE C2",
        Style::default()
            .fg(RED)
            .add_modifier(Modifier::BOLD),
    );

    let sep = Span::styled("  │  ", Style::default().fg(GRAY));

    let srv = Span::styled(
        format!("{}", app.server_name),
        Style::default().fg(LGRAY),
    );

    let ops = Span::styled(
        format!("  │  {} operator(s)", app.operators.len()),
        Style::default().fg(GRAY),
    );

    let right_pad = Span::raw("");

    let line = Line::from(vec![conn_dot, title, sep, srv, ops, right_pad]);
    let p    = Paragraph::new(line)
        .style(Style::default().bg(BG_BAR))
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(p, area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let selected = Tab::all().iter().position(|t| t == &app.tab).unwrap_or(0);

    // Count indicators per tab
    let session_count = app.agents.len();
    let listen_count  = app.listeners.len();
    let loot_count    = app.loot.len();

    let titles: Vec<Line> = Tab::all()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let count = match t {
                Tab::Sessions  => if session_count > 0 { format!("({})", session_count) } else { String::new() },
                Tab::Listeners => if listen_count  > 0 { format!("({})", listen_count)  } else { String::new() },
                Tab::Loot      => if loot_count    > 0 { format!("({})", loot_count)    } else { String::new() },
                _ => String::new(),
            };
            Line::from(format!(
                " {} {} {} [{}] ",
                t.icon(), t.title(), count, i + 1
            ))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::NONE).style(Style::default().bg(BG_BAR)))
        .select(selected)
        .style(Style::default().fg(GRAY).bg(BG_BAR))
        .highlight_style(
            Style::default()
                .fg(RED)
                .bg(BG_SEL)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled("│", Style::default().fg(GRAY)));

    f.render_widget(tabs, area);
}

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    use chrono::Utc;

    let (conn_str, conn_color) = if app.connected {
        ("● CONNECTED", GREEN)
    } else {
        ("● OFFLINE   ", RED)
    };

    let now = Utc::now().format("%H:%M:%S UTC").to_string();

    let status = Line::from(vec![
        Span::styled(format!(" {conn_str} "), Style::default().fg(conn_color).bg(BG_BAR)),
        Span::styled("│", Style::default().fg(GRAY).bg(BG_BAR)),
        Span::styled(
            format!(" Sessions: {} ", app.agents.len()),
            Style::default().fg(if app.agents.is_empty() { GRAY } else { GREEN }).bg(BG_BAR),
        ),
        Span::styled("│", Style::default().fg(GRAY).bg(BG_BAR)),
        Span::styled(
            format!(" Listeners: {} ", app.listeners.len()),
            Style::default().fg(if app.listeners.is_empty() { GRAY } else { CYAN }).bg(BG_BAR),
        ),
        Span::styled("│", Style::default().fg(GRAY).bg(BG_BAR)),
        Span::styled(
            format!(" Tasks: {} ", app.tasks.len()),
            Style::default().fg(LGRAY).bg(BG_BAR),
        ),
        Span::styled("│", Style::default().fg(GRAY).bg(BG_BAR)),
        Span::styled(
            format!(" Loot: {} ", app.loot.len()),
            Style::default().fg(if app.loot.is_empty() { GRAY } else { ORANGE }).bg(BG_BAR),
        ),
        Span::styled("│", Style::default().fg(GRAY).bg(BG_BAR)),
        Span::styled(
            format!(" {now} "),
            Style::default().fg(GRAY).bg(BG_BAR),
        ),
        Span::styled(
            " [1-6] tabs  [Tab] cycle  [i] insert  [q] quit ",
            Style::default().fg(Color::Rgb(60, 60, 60)).bg(BG_BAR),
        ),
    ]);

    let p = Paragraph::new(status).style(Style::default().bg(BG_BAR));
    f.render_widget(p, area);
}

