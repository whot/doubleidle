// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod client;
mod server;

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
        /// The port to connect to
        #[arg(long, default_value = "24999")]
        port: u16,

        /// Seconds between server → client activity notifications
        #[arg(long, default_value = "30")]
        interval: u64,
    },
    /// Run a doubleidle client (do this on the secondary machine)
    Client {
        /// The maximum client-local idle time before we reset the idle time
        #[arg(long, default_value = "4")]
        idletime_minutes: u64,

        /// doubleidle server host to connect to
        #[arg(value_name = "HOST[:PORT]")]
        address: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
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
            info!(
                "Starting server on port {} with interval {}s",
                port, interval
            );
            server::run(port, interval).await?;
        }
        Commands::Client {
            idletime_minutes,
            address,
        } => {
            info!(
                "Starting client connecting to {} with idle time threshold of {} minutes",
                address, idletime_minutes
            );
            client::run(address, idletime_minutes).await?;
        }
    }

    Ok(())
}
