// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use ashpd::desktop::remote_desktop::{DeviceType, RemoteDesktop};
use ashpd::desktop::PersistMode;
use ashpd::WindowIdentifier;
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time;

const HANDSHAKE: &str = "DOUBLEIDLE\n";
const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_PORT: u16 = 24999;

// XDG restore token location
fn get_restore_token_path() -> Result<PathBuf> {
    let xdg_cache_dir = dirs::cache_dir()
        .or_else(|| std::env::var("XDG_CACHE_HOME").ok().map(PathBuf::from))
        .context("Could not determine cache directory")?;

    let crate_name = env!("CARGO_PKG_NAME");
    let cache_dir = xdg_cache_dir.join(crate_name);
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("Failed to create cache directory: {cache_dir:?}"))?;

    Ok(cache_dir.join("restore_token.txt"))
}

// XDG restore token location
async fn load_restore_token(path: &PathBuf) -> Option<String> {
    match tokio::fs::read_to_string(path).await {
        Ok(token) => {
            let token = token.trim().to_string();
            if token.is_empty() {
                None
            } else {
                Some(token)
            }
        }
        Err(_) => {
            debug!("No existing restore token found");
            None
        }
    }
}

async fn save_restore_token(path: &PathBuf, token: &str) -> Result<()> {
    tokio::fs::write(path, token)
        .await
        .with_context(|| format!("Failed to write restore token to {path:?}"))?;
    Ok(())
}

fn parse_address(address: &str) -> Result<(String, u16)> {
    if let Some((host, port_str)) = address.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .with_context(|| format!("Invalid port: {}", port_str))?;
        Ok((host.to_string(), port))
    } else {
        Ok((address.to_string(), DEFAULT_PORT))
    }
}

/// Connect to the server and read the periotic idletime data.
///
/// idletimedata is saved into `server_idle_time` for processing by the caller.
async fn connect_and_read_idle_time(
    host: &str,
    port: u16,
    server_idle_time: Arc<Mutex<Duration>>,
) -> Result<()> {
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))
        .await
        .with_context(|| format!("Failed to connect to {}:{}", host, port))?;

    debug!("Connected to server, sending handshake");

    stream
        .write_all(HANDSHAKE.as_bytes())
        .await
        .context("Failed to send handshake")?;
    stream.flush().await.context("Failed to flush handshake")?;

    debug!("Handshake sent successfully");

    let mut buf = [0u8; 8];
    loop {
        match stream.read_exact(&mut buf).await {
            Ok(_) => {
                let idle_secs = u64::from_be_bytes(buf);
                let idle_duration = Duration::from_secs(idle_secs);

                debug!("Received server idle time: {:?}", idle_duration);

                let mut server_idle = server_idle_time.lock().await;
                *server_idle = idle_duration;
            }
            Err(e) => {
                anyhow::bail!("Failed to read from server: {}", e);
            }
        }
    }
}

/// Connect to the server given in address. Once connected,
/// monitor events from the server and whenever our *own* idle
/// time exceeds the threshold, send a tiny fake motion event - provided
/// the server wasn't idle past the threshold.
pub async fn run(address: String, idletime_minutes: u64) -> Result<()> {
    let (host, port) = parse_address(&address)?;
    let idletime_threshold = Duration::from_secs(idletime_minutes * 60);

    let server_idle_time = Arc::new(Mutex::new(Duration::ZERO));

    let restore_token_path = get_restore_token_path()?;
    let restore_token = load_restore_token(&restore_token_path).await;

    info!("Setting up RemoteDesktop portal session");

    let proxy = RemoteDesktop::new()
        .await
        .context("Failed to create RemoteDesktop proxy")?;

    let session = proxy
        .create_session()
        .await
        .context("Failed to create portal session")?;

    let devices = DeviceType::Pointer.into();
    let persist_mode = PersistMode::ExplicitlyRevoked;

    proxy
        .select_devices(&session, devices, restore_token.as_deref(), persist_mode)
        .await
        .context("Failed to select devices")?;

    let start_response = proxy
        .start(&session, Some(&WindowIdentifier::from_xid(0)))
        .await
        .context("Failed to start session")?;

    if let Ok(data) = start_response.response() {
        if let Some(token) = data.restore_token() {
            if let Err(e) = save_restore_token(&restore_token_path, token).await {
                warn!("Failed to save restore token: {}", e);
            }
        }
    }

    // The bit we write into
    let server_idle_time_w = server_idle_time.clone();

    // Connect to the server and read the idle time in a separate task
    // so we can run concurrently
    tokio::spawn(async move {
        loop {
            info!("Connecting to {}:{}", host, port);
            match connect_and_read_idle_time(&host, port, server_idle_time_w.clone()).await {
                Ok(_) => {
                    info!("Connection closed normally");
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                    info!("Retrying in {} seconds", RECONNECT_INTERVAL.as_secs());
                    time::sleep(RECONNECT_INTERVAL).await;
                }
            }
        }
    });

    info!(
        "Starting idle monitor with threshold of {} seconds",
        idletime_threshold.as_secs()
    );

    let mut go_right = true; // alternate right/left mouse motion

    loop {
        time::sleep(IDLE_CHECK_INTERVAL).await;

        // Apparently system_idle_time isnt async compatible so we need
        // to spawn that off for the read
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let idle = system_idle_time::get_idle_time().unwrap_or(Duration::ZERO);
            let _ = tx.send(idle);
        });

        let local_idle = rx.await.unwrap_or(Duration::ZERO);

        debug!("Local idle time: {:?}", local_idle);

        // We've been idle past the threshold, check if our server
        // was idle too.
        if local_idle >= idletime_threshold {
            let server_idle = {
                let idle_time = server_idle_time.lock().await;
                *idle_time
            };

            debug!("Local idle: {local_idle:?}, server idle: {server_idle:?}",);

            // Server had some event less than our threshold, so let's fake a motion event.
            //
            // This isn't very precise, if the server moved 4:59 min ago on a 5:00 timeout
            // we effectively extend by another 5:00 minutes. Shouldn't matter in real life,
            // I expect.
            if server_idle < idletime_threshold {
                let (dx, dy) = if go_right { (1.0, 1.0) } else { (-1.0, -1.0) };
                go_right = !go_right;

                info!("Local system idle but server active, waking ourselves up");

                if let Err(e) = proxy.notify_pointer_motion(&session, dx, dy).await {
                    error!("Failed to send motion event: {}", e);
                }
            }
        }
    }
}
