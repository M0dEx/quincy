use std::process::exit;

use anyhow::Result;
use clap::Parser;
use quincy::config::{FromPath, ServerConfig};
use quincy::server::QuincyServer;
use quincy::utils::cli::Args;
use quincy::utils::tracing::log_subscriber;
use tracing::error;
use tun2::AsyncDevice;

#[tokio::main]
async fn main() {
    // Enable default tracing to log errors before the configuration is loaded.
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));

    match run_server().await {
        Ok(_) => {}
        Err(e) => {
            error!("A critical error occurred: {e}");
            exit(1)
        }
    }
}

/// Runs the Quincy server.
async fn run_server() -> Result<()> {
    let args = Args::try_parse()?;
    let config = ServerConfig::from_path(&args.config_path, &args.env_prefix)?;
    // Enable tracing with the log level from the configuration.
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let server = QuincyServer::new(config)?;
    server.run::<AsyncDevice>().await
}
