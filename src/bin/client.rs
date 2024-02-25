use std::process::exit;

use anyhow::Result;
use clap::Parser;
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, FromPath};
use quincy::utils::cli::Args;
use quincy::utils::tracing::log_subscriber;
use tracing::error;
use tun2::AsyncDevice;

#[tokio::main]
async fn main() {
    // Enable default tracing to log errors before the configuration is loaded.
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));

    match run_client().await {
        Ok(_) => {}
        Err(e) => {
            error!("A critical error occurred: {e}");
            exit(1);
        }
    }
}

/// Runs the Quincy client.
async fn run_client() -> Result<()> {
    let args = Args::try_parse()?;
    let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
    // Enable tracing with the log level from the configuration.
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let client = QuincyClient::new(config);
    client.run::<AsyncDevice>().await
}
