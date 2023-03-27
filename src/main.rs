mod auth;
mod certificates;
mod client;
mod config;
mod connection;
mod constants;
mod server;
mod tunnel;
mod utils;

use crate::client::run_client;
use crate::config::{ClientConfig, FromPath, Mode, ServerConfig};
use crate::server::QuincyServer;
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    /// Whether this instance is a client or a server
    #[arg(long, default_value = "client")]
    mode: Mode,
    #[arg(long, default_value = "client.toml")]
    config_path: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    env_prefix: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = Args::parse();

    match args.mode {
        Mode::Client => {
            let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
            enable_tracing(&config.log.level);

            run_client(config).await
        }
        Mode::Server => {
            let config = ServerConfig::from_path(&args.config_path, &args.env_prefix)?;
            enable_tracing(&config.log.level);

            let mut server = QuincyServer::new(config).await?;
            server.run().await
        }
    }
}

fn enable_tracing(log_level: &str) {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    let subscriber = registry.with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
