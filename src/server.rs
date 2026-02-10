// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time;

const HANDSHAKE: &str = "DOUBLEIDLE";

pub async fn run(port: u16, interval_secs: u64) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .with_context(|| format!("Failed to bind to port {}", port))?;

    info!("Server listening on port {}", port);

    let (tx, _rx) = broadcast::channel::<Duration>(16);

    let idle_tx = tx.clone();
    let send_interval = Duration::from_secs(interval_secs);
    tokio::spawn(async move {
        if let Err(e) = monitor_idle_state(idle_tx, send_interval).await {
            error!("Idle monitor task failed: {}", e);
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("New connection from {}", addr);
                let rx = tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, rx).await {
                        warn!("Client {} error: {}", addr, e);
                    }
                    debug!("Client {} disconnected", addr);
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn monitor_idle_state(
    tx: broadcast::Sender<Duration>,
    send_interval: Duration,
) -> Result<()> {
    let mut interval = time::interval(send_interval);

    interval.tick().await;

    loop {
        interval.tick().await;

        // Apparently system_idle_time isnt async compatible so we need
        // to spawn that off for the read
        let (idle_tx, idle_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let idle = system_idle_time::get_idle_time().unwrap_or(Duration::ZERO);
            let _ = idle_tx.send(idle);
        });

        let idle_duration = idle_rx.await.unwrap_or(Duration::ZERO);

        debug!("System idle time: {:?}", idle_duration);

        let _ = tx.send(idle_duration);
    }
}

async fn handle_client(mut stream: TcpStream, mut rx: broadcast::Receiver<Duration>) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut handshake = String::new();
    tokio::select! {
        result = reader.read_line(&mut handshake) => {
            result.context("Failed to read handshake")?;
        }
        _ = time::sleep(Duration::from_secs(5)) => {
            anyhow::bail!("Handshake timeout");
        }
    }

    let handshake = handshake.trim();
    if handshake != HANDSHAKE {
        warn!("Invalid handshake: {}", handshake);
        anyhow::bail!("Invalid handshake");
    }

    info!("Client authenticated successfully");

    loop {
        match rx.recv().await {
            Ok(idle_duration) => {
                let idle_secs = idle_duration.as_secs();
                let bytes = idle_secs.to_be_bytes();

                if let Err(e) = writer.write_all(&bytes).await {
                    error!("Failed to write to client: {}", e);
                    break;
                }

                if let Err(e) = writer.flush().await {
                    error!("Failed to flush to client: {}", e);
                    break;
                }

                debug!("Sent idle time {} seconds to client", idle_secs);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("Client lagged behind by {} messages", n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("Broadcast channel closed");
                break;
            }
        }
    }

    Ok(())
}
