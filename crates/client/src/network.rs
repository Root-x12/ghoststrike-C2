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

    // Create a channel so the app can send messages to the server.
    let (ws_tx, mut ws_rx) = mpsc::channel::<OperatorMsg>(64);
    let _ = event_tx.send(Event::WsConnected(ws_tx)).await;

    // Spawn write task: app → server
    let mut write_task = tokio::spawn(async move {
        // After auth, request initial state.
        let init_msgs = [
            serde_json::to_string(&OperatorMsg::ListListeners).unwrap(),
            serde_json::to_string(&OperatorMsg::ListAgents).unwrap(),
        ];
        for json in &init_msgs {
            if write.send(Message::Text(json.clone())).await.is_err() {
                return;
            }
        }
        // Forward app-sourced messages.
        while let Some(msg) = ws_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if write.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    // Read loop: server → app
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(op_msg) = serde_json::from_str::<OperatorMsg>(&text) {
                            let _ = event_tx.send(Event::Server(op_msg)).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        warn!("WebSocket error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
            _ = &mut write_task => { break; }
        }
    }

    let _ = event_tx.send(Event::WsDisconnected).await;
    Ok(())
}
