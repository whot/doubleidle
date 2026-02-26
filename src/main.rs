// SPDX-License-Identifier: GPL-3.0-or-later

//! Keep a machine from suspending while another machine is active.
//!
//! You've got two machines. One is your main desktop that you actually use, the other is
//! something you need to glance at periodically - maybe a reference manual, logs, or a
//! terminal you check occasionally. The problem: that second machine locks itself because
//! you're not actively using it, and now you're stuck typing passwords all day.
//!
//! Disabling the screen lock isn't an option because security matters.
//!
//! `doubleidle` fixes this. Run the server on the machine you're actively using, and the
//! client on the machines you want to keep awake. The client prevents suspension and screen
//! locking via the [Inhibit portal] while the server is active (below its idle threshold).
//! When the server goes idle past the threshold, the client drops the lock and lets the
//! machine do its thing.
//!
//! [Inhibit portal]: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Inhibit.html
//!
//! # Example
//!
//! Start the server on your main machine:
//!
//! ```console
//! $ doubleidle server
//! [10:37 INFO ] Starting server on port 24999 with interval 30s
//! [10:37 INFO ] Generated new fingerprint and saved to "/home/user/.config/doubleidle/server-fingerprint.txt"
//! [10:37 INFO ] Server fingerprint: 9e754f83-712f-4cce-8ce5-ab0eb7e660e9
//! [10:37 INFO ] Server listening on port 24999
//! ```
//!
//! On first startup, the server generates a UUID fingerprint and saves it. You'll need this
//! to authorize clients. The fingerprint doesn't have to be a UUID - you can replace it with
//! any string you want, but UUIDs work fine.
//!
//! Start the client on the secondary machine (with zeroconf enabled):
//!
//! ```console
//! $ doubleidle client --allow=9e754f83-712f-4cce-8ce5-ab0eb7e660e9
//! [10:38 INFO ] Using 1 fingerprints from command line allowlist
//! [10:38 INFO ] Starting client with mDNS discovery, idle threshold 240 seconds
//! [10:38 INFO ] Discovering doubleidle servers via mDNS...
//! [10:38 INFO ] Discovered server at main-machine.local:24999
//! [10:38 INFO ] Connecting to main-machine.local:24999
//! [10:38 INFO ] Server fingerprint verified: 9e754f83-712f-4cce-8ce5-ab0eb7e660e9
//! [10:38 INFO ] Server active (30s), creating inhibit lock
//! [10:38 INFO ] Inhibit lock created successfully
//! ```
//!
//! Without zeroconf, specify the server address explicitly:
//!
//! ```console
//! $ doubleidle client --allow=9e754f83-712f-4cce-8ce5-ab0eb7e660e9 main-machine.local
//! ```
//!
//! The client only connects to servers with an allowed fingerprint. You can pass fingerprints
//! on the command line with `--allow`, or create `$XDG_CONFIG_HOME/doubleidle/allowed-servers.txt`
//! with one fingerprint per line. If you use `--allow`, the file is ignored.
//!
//! # How it works
//!
//! The server monitors idle time on the machine it's running on and broadcasts that information
//! to connected clients. Clients use this to decide whether to hold an inhibit lock.
//!
//! When the server's idle time is below the client's threshold, the client creates an inhibit
//! lock via the [Inhibit portal], preventing the system from suspending or engaging the
//! screensaver. Once the server goes idle past the threshold (or disconnects), the client
//! drops the lock.
//!
//! The server sends idle time updates at regular intervals (default: 30 seconds). Clients
//! also use a timer to drop the lock at the right time even if the server stops sending
//! updates.
//!
//! # Security
//!
//! Servers identify themselves with a fingerprint - a string saved to
//! `$XDG_CONFIG_HOME/doubleidle/server-fingerprint.txt`. On first startup, the server
//! generates a random UUID, but you can replace it with any string.
//!
//! Clients only connect to servers whose fingerprints are in their allowlist. This prevents
//! random servers on your network from controlling your machine's idle behavior.
//!
//! Fingerprints are not secret - they're sent over the network in plaintext. They exist to
//! prevent accidental connections, not to provide cryptographic authentication. If you need
//! real security, use a firewall or run doubleidle over a VPN.
//!
//! # Command-line options
//!
//! ## Server
//!
//! ```console
//! $ doubleidle server [--port PORT] [--interval INTERVAL]
//! ```
//!
//! - `--port`: TCP port to listen on (default: 24999)
//! - `--interval`: How often to send idle time updates to clients. Takes a number with
//!   optional suffix: `30` or `30s` for seconds, `5min` for minutes (default: 30 seconds)
//!
//! ## Client
//!
//! ```console
//! $ doubleidle client [OPTIONS] [HOST[:PORT]]
//! ```
//!
//! - `HOST[:PORT]`: Server address to connect to. If omitted, discovers server via mDNS
//!   (requires zeroconf support). Supports IPv4, IPv6, and hostnames.
//! - `--idletime`: Maximum idle time threshold before dropping the inhibit lock. Takes a
//!   number with optional suffix: `240` or `240s` for seconds, `4min` for minutes
//!   (default: 240 seconds)
//! - `--allow`: Semicolon-separated list of allowed server fingerprints. If provided,
//!   `allowed-servers.txt` is ignored.
//!
//! # Building
//!
//! Build with zeroconf support for automatic server discovery:
//!
//! ```console
//! $ cargo build --features zeroconf
//! ```
//!
//! On Ubuntu/Debian, you'll need: `apt install libclang-dev libavahi-client-dev`
//! On Fedora: `dnf install clang-devel avahi-devel`
//!
//! Without zeroconf (no dependencies, but you must specify server addresses manually):
//!
//! ```console
//! $ cargo build --no-default-features
//! ```

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

mod client;
mod server;

/// Get the application config directory, creating it if it doesn't exist
pub fn get_config_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .context("Failed to get config directory")?
        .join("doubleidle");

    // Create directory if it doesn't exist
    if !config_dir.exists() {
        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

        // Set restrictive permissions on Unix systems only when creating
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&config_dir)
                .with_context(|| format!("Failed to read metadata for {:?}", config_dir))?
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&config_dir, perms)
                .with_context(|| format!("Failed to set permissions for {:?}", config_dir))?;
        }
    }

    Ok(config_dir)
}

/// Parse a time value with optional suffix (s for seconds, min for minutes)
/// Defaults to seconds if no suffix is provided
fn parse_time_value(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Some(value_str) = s.strip_suffix("min") {
        let value = value_str
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid number: {}", value_str))?;
        value
            .checked_mul(60)
            .ok_or_else(|| anyhow!("Time value too large: {} minutes exceeds maximum", value))
    } else if let Some(value_str) = s.strip_suffix("s") {
        let value = value_str
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid number: {}", value_str))?;
        Ok(value)
    } else {
        // No suffix, default to seconds
        s.parse::<u64>()
            .map_err(|_| anyhow!("Invalid number: {}", s))
    }
}

#[derive(Parser)]
#[command(name = "doubleidle")]
#[command(about = "Keep client system from engaging screen saver while server is active")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a doubleidle server (do this on the machine you use actively)
    Server {
        /// The port to listen on
        #[arg(long, default_value = "24999")]
        port: u16,

        /// Time interval between server → client activity notifications (default: seconds, suffix with 's' or 'min')
        #[arg(long, default_value = "30")]
        interval: String,
    },
    /// Run a doubleidle client (do this on the secondary machine)
    Client {
        /// The maximum idle time threshold (default: seconds, suffix with 's' or 'min')
        #[arg(long, default_value = "240")]
        idletime: String,

        /// Server address (HOST\[:PORT\]). If omitted, discovers server via mDNS.
        #[arg(value_name = "HOST[:PORT]")]
        address: Option<String>,

        /// Semicolon-separated list of allowed server fingerprints. If provided, fingerprints are not loaded from file.
        #[arg(long, value_name = "FINGERPRINT;...", alias = "allow")]
        allowlist: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("zeroconf_tokio", log::LevelFilter::Off)
        .filter_module("zeroconf", log::LevelFilter::Off)
        .format(|buf, record| {
            use std::io::Write;
            let now = chrono::Local::now();
            writeln!(
                buf,
                "[{} {:5}] {}",
                now.format("%H:%M"),
                record.level(),
                record.args()
            )
        })
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port, interval } => {
            let interval_seconds = parse_time_value(&interval)?;

            if interval_seconds < 1 {
                anyhow::bail!(
                    "Interval must be at least 1 second, got {}",
                    interval_seconds
                );
            }

            info!(
                "Starting server on port {} with interval {}s",
                port, interval_seconds
            );
            server::run(port, interval_seconds).await?;
        }
        Commands::Client {
            idletime,
            address,
            allowlist,
        } => {
            let idletime_seconds = parse_time_value(&idletime)?;
            if idletime_seconds < 1 {
                anyhow::bail!(
                    "Idle time threshold must be at least 1 second, got {}",
                    idletime_seconds
                );
            }

            if let Some(ref address) = address {
                info!(
                    "Starting client connecting to {}, idle threshold {} seconds",
                    address, idletime_seconds
                );
            } else {
                info!(
                    "Starting client with mDNS discovery, idle threshold {} seconds",
                    idletime_seconds
                );
            }
            client::run(address, idletime_seconds, allowlist).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_time_value() {
        // Plain numbers default to seconds
        assert_eq!(parse_time_value("30").unwrap(), 30);
        assert_eq!(parse_time_value("240").unwrap(), 240);

        // Explicit seconds suffix
        assert_eq!(parse_time_value("30s").unwrap(), 30);
        assert_eq!(parse_time_value("5s").unwrap(), 5);

        // Minutes suffix
        assert_eq!(parse_time_value("5min").unwrap(), 300);
        assert_eq!(parse_time_value("2min").unwrap(), 120);
        assert_eq!(parse_time_value("1min").unwrap(), 60);

        // With whitespace
        assert_eq!(parse_time_value("  30  ").unwrap(), 30);
        assert_eq!(parse_time_value("5 min").unwrap(), 300);
        assert_eq!(parse_time_value("10 s").unwrap(), 10);

        // Invalid inputs
        assert!(parse_time_value("invalid").is_err());
        assert!(parse_time_value("").is_err());
        assert_eq!(parse_time_value("0").unwrap(), 0);
        assert_eq!(parse_time_value("0s").unwrap(), 0);
        assert_eq!(parse_time_value("0min").unwrap(), 0);

        // Overflow check
        assert!(parse_time_value("18446744073709551615min").is_err());
    }
}
