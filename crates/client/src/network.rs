use anyhow::Result;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};

use ghoststrike_common::OperatorMsg;
use crate::app::Event;

pub async fn connect(url: String, password: String, event_tx: mpsc::Sender<Event>) {
    loop {
        match try_connect(&url, &password, event_tx.clone()).await {
            Ok(_)  => {}
            Err(e) => {
                warn!("Connection error: {e} — retrying in 3s");
                let _ = event_tx
                    .send(Event::Server(OperatorMsg::Error {
                        message: format!("Disconnected: {e}"),
                    }))
                    .await;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}

async fn try_connect(
    url:      &str,
    password: &str,
    event_tx: mpsc::Sender<Event>,
) -> Result<()> {
    info!("Connecting to {url}");
    let (ws, _) = connect_async(url).await?;
    let (mut write, mut read) = ws.split();

    // Authenticate
    let auth = OperatorMsg::Auth { password: password.to_string() };
    write
        .send(Message::Text(serde_json::to_string(&auth)?))
        .await?;

    // After auth, request initial state
    let req_listeners = serde_json::to_string(&OperatorMsg::ListListeners)?;
    let req_agents    = serde_json::to_string(&OperatorMsg::ListAgents)?;
    write.send(Message::Text(req_listeners)).await?;
    write.send(Message::Text(req_agents)).await?;

    // Forward incoming server messages to the app
    while let Some(msg) = read.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                if let Ok(op_msg) = serde_json::from_str::<OperatorMsg>(&text) {
                    let _ = event_tx.send(Event::Server(op_msg)).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}
