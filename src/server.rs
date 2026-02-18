// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time;
use uuid::Uuid;
#[cfg(feature = "zeroconf")]
use zeroconf_tokio::{prelude::*, MdnsService, MdnsServiceAsync, ServiceType};

const HANDSHAKE: &str = "DOUBLEIDLE";
const MAX_FINGERPRINT_LENGTH: usize = 1024;

fn load_or_generate_fingerprint() -> Result<String> {
    let config_dir = crate::get_config_dir()?;
    let fingerprint_path = config_dir.join("server-fingerprint.txt");

    if fingerprint_path.exists() {
        let fingerprint_raw = std::fs::read_to_string(&fingerprint_path)
            .with_context(|| format!("Failed to read fingerprint from {:?}", fingerprint_path))?;

        let fingerprint = fingerprint_raw.trim().to_string();

        if fingerprint.is_empty() {
            anyhow::bail!("Fingerprint file at {:?} is empty", fingerprint_path);
        }

        // Check for embedded newlines (after trimming leading/trailing whitespace)
        if fingerprint.contains('\n') || fingerprint.contains('\r') {
            anyhow::bail!(
                "Fingerprint file at {:?} contains multiple lines or embedded newlines",
                fingerprint_path
            );
        }

        if fingerprint.len() > MAX_FINGERPRINT_LENGTH {
            anyhow::bail!(
                "Fingerprint in {:?} exceeds maximum length of {} bytes (got {})",
                fingerprint_path,
                MAX_FINGERPRINT_LENGTH,
                fingerprint.len()
            );
        }

        info!("Loaded existing fingerprint from {:?}", fingerprint_path);
        Ok(fingerprint)
    } else {
        let fingerprint = Uuid::new_v4().to_string();
        std::fs::write(&fingerprint_path, &fingerprint)
            .with_context(|| format!("Failed to write fingerprint to {:?}", fingerprint_path))?;

        // Set restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fingerprint_path)
                .with_context(|| format!("Failed to read metadata for {:?}", fingerprint_path))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&fingerprint_path, perms)
                .with_context(|| format!("Failed to set permissions for {:?}", fingerprint_path))?;
        }

        info!(
            "Generated new fingerprint and saved to {:?}",
            fingerprint_path
        );
        info!("Server fingerprint: {}", fingerprint);
        Ok(fingerprint)
    }
}

pub async fn run(port: u16, interval_secs: u64) -> Result<()> {
    let fingerprint = load_or_generate_fingerprint()?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .with_context(|| format!("Failed to bind to port {}", port))?;

    info!("Server listening on port {}", port);
    info!("Server fingerprint: {}", fingerprint);

    // Register mDNS service
    #[cfg(feature = "zeroconf")]
    let _service = {
        let service_type =
            ServiceType::new("doubleidle", "tcp").context("Failed to create service type")?;
        let mut service = MdnsService::new(service_type, port);
        service.set_name("doubleidle-server");

        let mut service_async =
            MdnsServiceAsync::new(service).context("Failed to create async service")?;

        match service_async.start().await {
            Ok(_) => {
                info!(
                    "Registered mDNS service: _doubleidle._tcp.local on port {}",
                    port
                );
                Some(service_async)
            }
            Err(e) => {
                warn!("Failed to register mDNS service: {}. Server will run but won't be discoverable.", e);
                None
            }
        }
    };

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
                let fp = fingerprint.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, rx, fp).await {
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

async fn handle_client(
    mut stream: TcpStream,
    mut rx: broadcast::Receiver<Duration>,
    fingerprint: String,
) -> Result<()> {
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

    // Send fingerprint to client
    writer
        .write_all(fingerprint.as_bytes())
        .await
        .context("Failed to send fingerprint")?;
    writer
        .write_all(b"\n")
        .await
        .context("Failed to send fingerprint newline")?;
    writer
        .flush()
        .await
        .context("Failed to flush fingerprint")?;

    debug!("Sent fingerprint to client");

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
