// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use log::info;

mod client;
mod server;

/// Parse a time value with optional suffix (s for seconds, min for minutes)
/// Defaults to seconds if no suffix is provided
fn parse_time_value(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Some(value_str) = s.strip_suffix("min") {
        let value = value_str.trim().parse::<u64>()
            .map_err(|_| anyhow!("Invalid number: {}", value_str))?;
        value.checked_mul(60)
            .ok_or_else(|| anyhow!("Time value too large: {} minutes exceeds maximum", value))
    } else if let Some(value_str) = s.strip_suffix("s") {
        let value = value_str.trim().parse::<u64>()
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

        /// Server address (HOST[:PORT]). If omitted, discovers server via mDNS.
        #[arg(value_name = "HOST[:PORT]")]
        address: Option<String>,
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
                anyhow::bail!("Interval must be at least 1 second, got {}", interval_seconds);
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
        } => {
            let idletime_seconds = parse_time_value(&idletime)?;
            if idletime_seconds < 1 {
                anyhow::bail!("Idle time threshold must be at least 1 second, got {}", idletime_seconds);
            }

            if let Some(ref address) = address {
                info!(
                    "Starting client connecting to {}, idle threshold {} seconds",
                    address,
                    idletime_seconds
                );
            } else {
                info!(
                    "Starting client with mDNS discovery, idle threshold {} seconds",
                    idletime_seconds
                );
            }
            client::run(address, idletime_seconds).await?;
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
        assert!(parse_time_value("0").unwrap() == 0);
        assert!(parse_time_value("0s").unwrap() == 0);
        assert!(parse_time_value("0min").unwrap() == 0);

        // Overflow check
        assert!(parse_time_value("18446744073709551615min").is_err());
    }
}
