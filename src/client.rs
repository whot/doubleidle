// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use ashpd::desktop::remote_desktop::{DeviceType, RemoteDesktop};
use ashpd::desktop::PersistMode;
use ashpd::WindowIdentifier;
#[cfg(feature = "zeroconf")]
use zeroconf_tokio::{prelude::*, BrowserEvent, MdnsBrowser, MdnsBrowserAsync, ServiceType};
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
const PORTAL_RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_PORT: u16 = 24999;

struct RestoreToken {
    token: String,
}

impl RestoreToken {
    fn new(token: &str) -> RestoreToken {
        RestoreToken {
            token: token.into(),
        }
    }

    /// This consumes the token to indicate that we can't do anything but save it.
    async fn save(self) -> Result<()> {
        let path = Self::token_path()?;
        tokio::fs::write(&path, self.token)
            .await
            .with_context(|| format!("Failed to write restore token to {path:?}"))?;
        Ok(())
    }

    fn token_path() -> Result<PathBuf> {
        let xdg_cache_dir = dirs::cache_dir()
            .or_else(|| std::env::var("XDG_CACHE_HOME").ok().map(PathBuf::from))
            .context("Could not determine cache directory")?;

        let crate_name = env!("CARGO_PKG_NAME");
        let cache_dir = xdg_cache_dir.join(crate_name);
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {cache_dir:?}"))?;

        Ok(cache_dir.join("restore_token.txt"))
    }

    async fn new_from_disk() -> Result<Option<RestoreToken>> {
        let path = Self::token_path()?;
        match tokio::fs::read_to_string(path).await {
            Ok(token) => {
                let token = token.trim().to_string();
                if token.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(RestoreToken { token }))
                }
            }
            Err(_) => {
                debug!("No existing restore token found");
                Ok(None)
            }
        }
    }
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

/// Discover a doubleidle server via mDNS/zeroconf
#[cfg(feature = "zeroconf")]
async fn discover_server(timeout: Duration) -> Result<Option<(String, u16)>> {
    info!("Discovering doubleidle servers via mDNS...");

    let service_type = ServiceType::new("doubleidle", "tcp")
        .context("Failed to create service type")?;
    let browser = MdnsBrowser::new(service_type);
    let mut browser_async = MdnsBrowserAsync::new(browser)
        .context("Failed to create async browser")?;

    browser_async.start_with_timeout(timeout).await
        .context("Failed to start mDNS browser")?;

    // Wait for first service discovery
    while let Some(event_result) = browser_async.next().await {
        match event_result {
            Ok(BrowserEvent::Add(service)) => {
                let host = service.host_name().to_string();
                let port = *service.port();
                info!("Discovered server at {}:{}", host, port);

                // Shutdown browser to clean up
                let _ = browser_async.shutdown().await;

                return Ok(Some((host, port)));
            }
            Ok(BrowserEvent::Remove(_)) => {
                debug!("Service removed, continuing search...");
                continue;
            }
            Err(e) => {
                debug!("Browser error: {}", e);
                continue;
            }
        }
    }

    // Timeout or no services found
    Ok(None)
}

struct PortalSession {
    proxy: RemoteDesktop<'static>,
    session: ashpd::desktop::Session<'static, RemoteDesktop<'static>>,
}

impl PortalSession {
    async fn notify_pointer_motion(&self, dx: f64, dy: f64) -> ashpd::Result<()> {
        self.proxy
            .notify_pointer_motion(&self.session, dx, dy)
            .await
    }
}

/// Setup the RemoteDesktop portal session for sending motion events
async fn setup_portal_session() -> Result<PortalSession> {
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

    let restore_token = RestoreToken::new_from_disk().await?;

    proxy
        .select_devices(
            &session,
            devices,
            restore_token.as_ref().map(|t| t.token.as_str()),
            persist_mode,
        )
        .await
        .context("Failed to select devices")?;

    let start_response = proxy
        .start(&session, Some(&WindowIdentifier::from_xid(0)))
        .await
        .context("Failed to start session")?;

    if let Ok(data) = start_response.response() {
        if let Some(token) = data.restore_token() {
            if let Err(e) = RestoreToken::new(token).save().await {
                warn!("Failed to save restore token: {}", e);
            }
        }
    }

    info!("RemoteDesktop portal session established successfully");
    Ok(PortalSession { proxy, session })
}

/// Connect to the server and read the periotic idletime data.
///
/// idletimedata is saved into `server_idle_time` for processing by the caller.
async fn connect_and_read_idle_time(
    host: &str,
    port: u16,
    server_idle_time: Arc<Mutex<Duration>>,
    server_connected: Arc<Mutex<bool>>,
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

    // Mark as connected
    {
        let mut connected = server_connected.lock().await;
        *connected = true;
    }

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
pub async fn run(address: Option<String>, idletime_seconds: u64) -> Result<()> {
    let (host, port) = match address {
        Some(addr) => parse_address(&addr)?,
        None => {
            #[cfg(feature = "zeroconf")]
            {
                match discover_server(Duration::from_secs(10)).await? {
                    Some(discovered) => discovered,
                    None => {
                        anyhow::bail!(
                            "No doubleidle server found via mDNS after 10 seconds.\n\
                             Try specifying the server address explicitly:\n  \
                             doubleidle client <server-hostname>"
                        );
                    }
                }
            }
            #[cfg(not(feature = "zeroconf"))]
            {
                anyhow::bail!(
                    "Server address required. Zeroconf support not enabled.\n\
                     Usage: doubleidle client <server-hostname>"
                );
            }
        }
    };
    let idletime_threshold = Duration::from_secs(idletime_seconds);

    let server_idle_time = Arc::new(Mutex::new(Duration::ZERO));
    let server_connected = Arc::new(Mutex::new(false));

    // Setup initial portal session
    let portal_session: Arc<Mutex<Option<PortalSession>>> = Arc::new(Mutex::new(
        match setup_portal_session().await {
            Ok(session) => Some(session),
            Err(e) => {
                warn!("Failed to setup initial portal session: {}", e);
                warn!("Will retry when server activity is detected");
                None
            }
        },
    ));

    let server_idle_time_w = server_idle_time.clone();
    let server_connected_w = server_connected.clone();

    // Connect to the server and read the idle time in a separate task
    // so we can run concurrently
    tokio::spawn(async move {
        loop {
            info!("Connecting to {}:{}", host, port);
            match connect_and_read_idle_time(&host, port, server_idle_time_w.clone(), server_connected_w.clone()).await {
                Ok(_) => {
                    info!("Connection closed normally");
                }
                Err(e) => {
                    // Mark as disconnected
                    {
                        let mut connected = server_connected_w.lock().await;
                        *connected = false;
                    }
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
    let mut last_portal_reconnect_attempt = time::Instant::now() - PORTAL_RECONNECT_INTERVAL;

    loop {
        let is_connected = {
            let connected = server_connected.lock().await;
            *connected
        };
        if !is_connected {
            continue;
        }

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

                // When the screen goes idle we lose the RD session, so let's try to get
                // a new one. This requires moving the devices on the remote machine but
                // that's just how it is. At least with the token there shouldn't be
                // any user dialog.
                let mut session_guard = portal_session.lock().await;
                if session_guard.is_none() {
                    if last_portal_reconnect_attempt.elapsed() >= PORTAL_RECONNECT_INTERVAL {
                        info!("Portal session lost, attempting to reconnect");
                        last_portal_reconnect_attempt = time::Instant::now();

                        match setup_portal_session().await {
                            Ok(new_session) => {
                                info!("Portal session reconnected successfully");
                                *session_guard = Some(new_session);
                            }
                            Err(e) => {
                                error!("Failed to reconnect portal session: {}", e);
                                error!(
                                    "Will retry in {} seconds",
                                    PORTAL_RECONNECT_INTERVAL.as_secs()
                                );
                            }
                        }
                    }
                }

                // Try to send motion event if we have a session
                if let Some(portal) = session_guard.as_ref() {
                    let (dx, dy) = if go_right { (1.0, 1.0) } else { (-1.0, -1.0) };
                    go_right = !go_right;

                    info!("Local system idle but server active, waking ourselves up");

                    if let Err(e) = portal.notify_pointer_motion(dx, dy).await {
                        error!("Failed to send motion event: {}", e);
                        warn!("Marking portal session as lost");
                        *session_guard = None;
                        last_portal_reconnect_attempt = time::Instant::now();
                    }
                }
            }
        }
    }
}
