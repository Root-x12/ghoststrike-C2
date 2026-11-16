mod app;
mod network;
mod ui;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

use app::{App, Event};

#[derive(Parser)]
#[command(name = "ghoststrike", version)]
struct Args {
    /// Team server WebSocket URL
    #[arg(short, long, default_value = "ws://127.0.0.1:8443/ws")]
    server: String,

    /// Operator password
    #[arg(short, long, default_value = "ghoststrike")]
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let result = run(&mut term, args).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    result
}

async fn run(
    term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    args: Args,
) -> Result<()> {
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<Event>(64);

    // Spawn network task
    let net_handle = tokio::spawn(network::connect(
        args.server,
        args.password,
        event_tx.clone(),
    ));

    // Spawn input task
    let input_tx = event_tx.clone();
    tokio::spawn(async move {
        use crossterm::event::{EventStream, Event as CEvent, KeyCode};
        use futures::StreamExt;
        let mut reader = EventStream::new();
        while let Some(Ok(ev)) = reader.next().await {
            if let CEvent::Key(key) = ev {
                let _ = input_tx.send(Event::Key(key)).await;
            }
        }
    });

    let mut app = App::new(event_tx.clone());

    loop {
        term.draw(|f| ui::draw(f, &app))?;

        match app.next_event(event_rx.recv()).await {
            Some(Event::Quit) => break,
            Some(e) => app.handle(e).await,
            None => break,
        }
    }

    net_handle.abort();
    Ok(())
}
