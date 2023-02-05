mod certificates;
mod client;
mod config;
mod connection;
mod constants;
mod server;
mod tun;
mod utils;

use crate::client::run_client;
use crate::config::{Config, Mode};
use crate::server::run_server;
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
    #[arg(long, default_value = "config.toml")]
    config_path: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    env_prefix: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = Args::parse();
    let config = Config::from_path(&args.config_path, &args.env_prefix, args.mode)?;

    enable_tracing(&config.log.level);

    match args.mode {
        Mode::CLIENT => run_client(config).await,
        Mode::SERVER => run_server(config).await,
    }
}

fn enable_tracing(log_level: &str) {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    let subscriber = registry.with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
