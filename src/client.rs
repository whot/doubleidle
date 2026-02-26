// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use ashpd::desktop::inhibit::{InhibitFlags, InhibitProxy};
use ashpd::desktop::Request;
use log::{debug, error, info};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time;
#[cfg(feature = "zeroconf")]
use zeroconf_tokio::{prelude::*, BrowserEvent, MdnsBrowser, MdnsBrowserAsync, ServiceType};

const HANDSHAKE: &str = "DOUBLEIDLE\n";
const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_PORT: u16 = 24999;
const TIMER_BUFFER: Duration = Duration::from_secs(5);
const ONE_DAY: Duration = Duration::from_secs(86400);
const MAX_FINGERPRINT_LENGTH: usize = 1024;

fn load_allowed_fingerprints() -> Result<HashSet<String>> {
    let config_dir = crate::get_config_dir()?;
    let allowed_servers_path = config_dir.join("allowed-servers.txt");

    if !allowed_servers_path.exists() {
        error!(
            "No allowed servers file found at {:?}",
            allowed_servers_path
        );
        anyhow::bail!(
            "No allowed servers file found. Create {:?} with one fingerprint per line, \
             or use --allow to specify fingerprints on the command line",
            allowed_servers_path
        );
    }

    let content = std::fs::read_to_string(&allowed_servers_path).with_context(|| {
        format!(
            "Failed to read allowed servers from {:?}",
            allowed_servers_path
        )
    })?;

    let fingerprints: HashSet<String> = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else if trimmed.len() > MAX_FINGERPRINT_LENGTH {
                error!(
                    "Fingerprint in {:?} exceeds maximum length of {} bytes: {:?}",
                    allowed_servers_path,
                    MAX_FINGERPRINT_LENGTH,
                    &trimmed[..MAX_FINGERPRINT_LENGTH.min(50)]
                );
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();

    if fingerprints.is_empty() {
        error!(
            "Allowed servers file at {:?} contains no valid fingerprints",
            allowed_servers_path
        );
        anyhow::bail!(
            "Allowed servers file at {:?} contains no valid fingerprints. \
             Add at least one fingerprint, or use --allow on the command line",
            allowed_servers_path
        );
    }

    info!(
        "Loaded {} allowed fingerprints from {:?}",
        fingerprints.len(),
        allowed_servers_path
    );
    Ok(fingerprints)
}

fn parse_address(address: &str) -> Result<(String, u16)> {
    // Handle [host]:port format (for IPv6 addresses)
    if let Some(addr) = address.strip_prefix('[') {
        if let Some((host, port_str)) = addr.split_once("]:") {
            let port = port_str
                .parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
            return Ok((host.to_string(), port));
        } else if let Some(host) = addr.strip_suffix(']') {
            return Ok((host.to_string(), DEFAULT_PORT));
        } else {
            anyhow::bail!("Invalid address format: missing closing bracket");
        }
    }

    // Handle host:port format (for IPv4 and hostnames)
    if let Some((host, port_str)) = address.rsplit_once(':') {
        // Check if this might be an IPv6 address without brackets
        // (contains more than one colon)
        if host.contains(':') {
            // This is likely a bare IPv6 address without port
            return Ok((address.to_string(), DEFAULT_PORT));
        }

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

    let service_type =
        ServiceType::new("doubleidle", "tcp").context("Failed to create service type")?;
    let browser = MdnsBrowser::new(service_type);
    let mut browser_async =
        MdnsBrowserAsync::new(browser).context("Failed to create async browser")?;

    browser_async
        .start_with_timeout(timeout)
        .await
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

/// Helper function to properly close and drop an inhibit request
async fn drop_inhibit_lock(inhibit_request: &Arc<Mutex<Option<Request<()>>>>, reason: &str) {
    // Take ownership of the request and drop the guard before awaiting
    let request = {
        let mut request_guard = inhibit_request.lock().await;
        request_guard.take()
    };

    if let Some(request) = request {
        info!("{}", reason);
        if let Err(e) = request.close().await {
            error!("Failed to close inhibit request: {}", e);
        }
    }
}

/// Connect to the server and read the periodic idletime data.
///
/// idletimedata is saved into `server_idle_time` for processing by the caller.
/// Sends a notification on `idle_update_notify` when a new idle time is received.
async fn connect_and_read_idle_time(
    host: &str,
    port: u16,
    server_idle_time: Arc<Mutex<Duration>>,
    server_connected: Arc<Mutex<bool>>,
    idle_update_notify: tokio::sync::mpsc::UnboundedSender<()>,
    allowed_fingerprints: HashSet<String>,
) -> Result<()> {
    // Format address for connection - wrap IPv6 addresses in brackets
    let connection_addr = if host.contains(':') {
        // IPv6 address needs brackets
        format!("[{}]:{}", host, port)
    } else {
        // IPv4 or hostname
        format!("{}:{}", host, port)
    };

    let mut stream = TcpStream::connect(&connection_addr)
        .await
        .with_context(|| format!("Failed to connect to {}", connection_addr))?;

    debug!("Connected to server, sending handshake");

    stream
        .write_all(HANDSHAKE.as_bytes())
        .await
        .context("Failed to send handshake")?;
    stream.flush().await.context("Failed to flush handshake")?;

    debug!("Handshake sent successfully");

    // Receive and verify fingerprint with bounded read
    let mut reader = BufReader::new(stream);
    let mut fingerprint_raw = String::new();
    let bytes_read = tokio::select! {
        result = reader.read_line(&mut fingerprint_raw) => {
            result.context("Failed to read fingerprint from server")?
        }
        _ = time::sleep(Duration::from_secs(5)) => {
            anyhow::bail!("Timeout waiting for server fingerprint");
        }
    };

    if bytes_read == 0 {
        error!("Server closed connection before sending fingerprint");
        anyhow::bail!("Server sent no fingerprint");
    }

    if fingerprint_raw.len() > MAX_FINGERPRINT_LENGTH {
        error!(
            "Fingerprint exceeds maximum length of {} bytes",
            MAX_FINGERPRINT_LENGTH
        );
        anyhow::bail!("Server sent invalid fingerprint (too long)");
    }

    let fingerprint = fingerprint_raw.trim().to_string();
    debug!("Received fingerprint from server: {}", fingerprint);

    if fingerprint.is_empty() {
        error!("Received empty fingerprint from server");
        anyhow::bail!("Server sent empty fingerprint");
    }

    if !allowed_fingerprints.contains(&fingerprint) {
        error!("Server fingerprint '{}' not in allowed list", fingerprint);
        anyhow::bail!(
            "Server fingerprint not authorized. Add '{}' to allowed-servers.txt or use --allow={}",
            fingerprint,
            fingerprint
        );
    }

    info!("Server fingerprint verified: {}", fingerprint);

    // Mark as connected
    {
        let mut connected = server_connected.lock().await;
        *connected = true;
    }

    let mut buf = [0u8; 8];
    loop {
        match reader.read_exact(&mut buf).await {
            Ok(_) => {
                let idle_secs = u64::from_be_bytes(buf);
                let idle_duration = Duration::from_secs(idle_secs);

                debug!("Received server idle time: {:?}", idle_duration);

                // Update server idle time
                let mut server_idle = server_idle_time.lock().await;
                *server_idle = idle_duration;
                drop(server_idle);

                // Notify main loop of new idle time
                if idle_update_notify.send(()).is_err() {
                    // Receiver dropped, main loop is gone
                    anyhow::bail!("Main loop channel closed");
                }
            }
            Err(e) => {
                anyhow::bail!("Failed to read from server: {}", e);
            }
        }
    }
}

/// Connect to the server given in address. Once connected,
/// use the Inhibit portal to prevent suspend/idle and keep reading
/// server idle time info. Once the server idle info goes past the threshold
/// drop the Inhibit lock.
pub async fn run(
    address: Option<String>,
    idletime_seconds: u64,
    allowlist: Option<String>,
) -> Result<()> {
    let allowed_fingerprints = if let Some(allowlist_str) = allowlist {
        // Parse semicolon-separated fingerprints from command line
        let fingerprints: HashSet<String> = allowlist_str
            .split(';')
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else if trimmed.len() > MAX_FINGERPRINT_LENGTH {
                    error!(
                        "Fingerprint in --allow argument exceeds maximum length of {} bytes",
                        MAX_FINGERPRINT_LENGTH
                    );
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();

        if fingerprints.is_empty() {
            anyhow::bail!("No valid fingerprints provided in --allow argument");
        }

        info!(
            "Using {} fingerprints from command line allowlist",
            fingerprints.len()
        );
        fingerprints
    } else {
        // Load from file
        load_allowed_fingerprints()?
    };

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

    // Setup Inhibit portal proxy
    let inhibit_proxy = InhibitProxy::new()
        .await
        .context("Failed to create Inhibit proxy")?;
    info!("Inhibit portal proxy created successfully");

    // Track the active inhibit request
    let inhibit_request: Arc<Mutex<Option<Request<()>>>> = Arc::new(Mutex::new(None));

    // Channel for notifying main loop of idle time updates
    let (idle_update_tx, mut idle_update_rx) = tokio::sync::mpsc::unbounded_channel();

    let server_idle_time_w = server_idle_time.clone();
    let server_connected_w = server_connected.clone();

    // Connect to the server and read the idle time in a separate task
    // so we can run concurrently
    tokio::spawn(async move {
        loop {
            info!("Connecting to {}:{}", host, port);
            match connect_and_read_idle_time(
                &host,
                port,
                server_idle_time_w.clone(),
                server_connected_w.clone(),
                idle_update_tx.clone(),
                allowed_fingerprints.clone(),
            )
            .await
            {
                Ok(_) => {
                    // Mark as disconnected and notify main loop
                    {
                        let mut connected = server_connected_w.lock().await;
                        *connected = false;
                    }
                    let _ = idle_update_tx.send(());
                    info!("Connection closed normally");
                    info!("Retrying in {} seconds", RECONNECT_INTERVAL.as_secs());
                    time::sleep(RECONNECT_INTERVAL).await;
                }
                Err(e) => {
                    // Mark as disconnected
                    {
                        let mut connected = server_connected_w.lock().await;
                        *connected = false;
                    }
                    // Notify main loop of disconnection to drop inhibit lock immediately
                    let _ = idle_update_tx.send(());
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

    let mut previous_server_idle: Option<Duration> = None;
    // Start with a very long sleep that will be replaced on first update
    let sleep = time::sleep(ONE_DAY);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            msg = idle_update_rx.recv() => {
                // Check if channel was closed (all senders dropped)
                if msg.is_none() {
                    error!("Server connection channel closed unexpectedly");
                    anyhow::bail!("Server connection channel closed");
                }

                // Received new idle time from server
                let is_connected = *server_connected.lock().await;

                if !is_connected {
                    // Drop inhibit lock immediately when server disconnects
                    drop_inhibit_lock(&inhibit_request, "Server disconnected, dropping inhibit lock").await;
                    // Reset timer since we're no longer tracking server state
                    sleep.as_mut().reset(time::Instant::now() + ONE_DAY);
                    previous_server_idle = None;
                    continue;
                }

                let server_idle = *server_idle_time.lock().await;

                debug!("Server idle update received: {:?} (previous: {:?})", server_idle, previous_server_idle);

                // Check if server is already past threshold
                if server_idle >= idletime_threshold {
                    debug!("Server idle ({:?}) already past threshold ({:?})", server_idle, idletime_threshold);
                    drop_inhibit_lock(
                        &inhibit_request,
                        &format!("Server idle ({:?}) past threshold ({:?}), dropping inhibit lock",
                            server_idle, idletime_threshold)
                    ).await;
                    // Reset timer to prevent unnecessary firing
                    sleep.as_mut().reset(time::Instant::now() + ONE_DAY);
                    previous_server_idle = Some(server_idle);
                    continue;
                }

                // Detect server activity or threshold crossing
                let should_have_lock = if let Some(prev) = previous_server_idle {
                    // Subsequent reading: check if activity detected
                    let activity = server_idle < prev;

                    if activity {
                        debug!("Server activity detected: idle went from {:?} to {:?}", prev, server_idle);
                        true
                    } else {
                        // No activity, maintain current lock state
                        inhibit_request.lock().await.is_some()
                    }
                } else {
                    // First reading: create lock since we're below threshold
                    true
                };

                let mut request_guard = inhibit_request.lock().await;

                if should_have_lock && request_guard.is_none() {
                    info!("Server active ({:?}), creating inhibit lock", server_idle);

                    let flags = InhibitFlags::Suspend | InhibitFlags::Idle;
                    match inhibit_proxy
                        .inhibit(None, flags, "Doubleidle server still active")
                        .await
                    {
                        Ok(request) => {
                            info!("Inhibit lock created successfully");
                            *request_guard = Some(request);
                        }
                        Err(e) => {
                            error!("Failed to create inhibit lock: {}", e);
                        }
                    }
                }

                drop(request_guard);

                // Reset the timer when server idle time doesn't increase (activity detected or
                // stayed same) or this is the first reading. The timer will drop the lock at
                // the right time even if the server doesn't notify us.
                if previous_server_idle.is_none_or(|prev| server_idle <= prev) {
                    let time_until_threshold = idletime_threshold.saturating_sub(server_idle);
                    let timer_duration = time_until_threshold + TIMER_BUFFER;

                    debug!("Setting drop timer for {:?} (server idle: {:?}, threshold: {:?}, buffer: {:?})",
                        timer_duration, server_idle, idletime_threshold, TIMER_BUFFER);

                    // Reset the timer
                    sleep.as_mut().reset(time::Instant::now() + timer_duration);
                }

                previous_server_idle = Some(server_idle);
            }

            _ = &mut sleep => {
                // Timer fired - server must have gone idle past threshold
                debug!("Drop timer fired");

                // Reset timer to prevent continuous firing
                sleep.as_mut().reset(time::Instant::now() + ONE_DAY);

                let is_connected = *server_connected.lock().await;

                if !is_connected {
                    drop_inhibit_lock(&inhibit_request, "Timer fired but server disconnected, dropping inhibit lock").await;
                    previous_server_idle = None;
                    continue;
                }

                let server_idle = *server_idle_time.lock().await;

                drop_inhibit_lock(
                    &inhibit_request,
                    &format!("Timer fired: server idle ({:?}) past threshold ({:?}), dropping inhibit lock",
                        server_idle, idletime_threshold)
                ).await;

                // Reset previous_server_idle so next update is treated as a fresh start
                // This ensures the lock will be recreated if server is still below threshold
                previous_server_idle = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_ipv4() {
        // IPv4 with port
        assert_eq!(
            parse_address("192.168.1.1:8080").unwrap(),
            ("192.168.1.1".to_string(), 8080)
        );

        // IPv4 without port (uses default)
        assert_eq!(
            parse_address("192.168.1.1").unwrap(),
            ("192.168.1.1".to_string(), DEFAULT_PORT)
        );
    }

    #[test]
    fn test_parse_address_hostname() {
        // Hostname with port
        assert_eq!(
            parse_address("example.com:8080").unwrap(),
            ("example.com".to_string(), 8080)
        );

        // Hostname without port
        assert_eq!(
            parse_address("example.com").unwrap(),
            ("example.com".to_string(), DEFAULT_PORT)
        );

        // Hostname with subdomain
        assert_eq!(
            parse_address("foo.bar.example.com:9999").unwrap(),
            ("foo.bar.example.com".to_string(), 9999)
        );
    }

    #[test]
    fn test_parse_address_ipv6_brackets() {
        // IPv6 with brackets and port
        assert_eq!(
            parse_address("[fe80::1]:8080").unwrap(),
            ("fe80::1".to_string(), 8080)
        );
        assert_eq!(
            parse_address("[::1]:24999").unwrap(),
            ("::1".to_string(), 24999)
        );
        assert_eq!(
            parse_address("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );

        // IPv6 with brackets but no port (uses default)
        assert_eq!(
            parse_address("[fe80::1]").unwrap(),
            ("fe80::1".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_address("[::1]").unwrap(),
            ("::1".to_string(), DEFAULT_PORT)
        );
    }

    #[test]
    fn test_parse_address_ipv6_bare() {
        // Bare IPv6 addresses without brackets (no port possible)
        assert_eq!(
            parse_address("fe80::1").unwrap(),
            ("fe80::1".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_address("::1").unwrap(),
            ("::1".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_address("2001:db8::1").unwrap(),
            ("2001:db8::1".to_string(), DEFAULT_PORT)
        );
        assert_eq!(
            parse_address("fe80::1:2345").unwrap(),
            ("fe80::1:2345".to_string(), DEFAULT_PORT)
        );
    }

    #[test]
    fn test_parse_address_invalid() {
        // Missing closing bracket
        assert!(parse_address("[fe80::1").is_err());

        // Invalid port
        assert!(parse_address("example.com:99999").is_err());
        assert!(parse_address("[fe80::1]:99999").is_err());
        assert!(parse_address("example.com:abc").is_err());
    }
}
