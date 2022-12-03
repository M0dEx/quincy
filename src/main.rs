mod utils;
mod client;
mod server;
mod connection;

use std::net::SocketAddr;
use std::process::exit;
use clap::Parser;
use tracing::error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use crate::client::run_client;
use crate::server::run_server;

#[derive(Copy, Clone)]
enum Mode {
    CLIENT,
    SERVER,
}

impl From<String> for Mode {
    fn from(s: String) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "server" => Mode::SERVER,
            _ => Mode::CLIENT,
        }
    }
}

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    /// Host to connect to or bind to
    #[arg(default_value = "127.0.0.1:55554")]
    host: SocketAddr,
    /// Whether this instance is a client or a server
    #[arg(long, default_value = "client")]
    mode: Mode,
    /// Number of bytes to send/receive
    #[arg(long, default_value = "1024")]
    data_size: u64,
    /// The time to run in seconds
    #[arg(long, default_value = "60")]
    duration: u64,
    /// Send buffer size in bytes
    #[arg(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[arg(long, default_value = "2097152")]
    recv_buffer_size: usize,
}

#[tokio::main]
async fn main() {
    enable_tracing();
    let args: Args = Args::parse();

    let res = match args.mode {
        Mode::CLIENT => run_client(args).await,
        Mode::SERVER => run_server(args).await,
    };

    if let Err(e) = res {
        error!("Caught an error: {:#}", e);
        exit(1);
    }
}

fn enable_tracing() {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new("info").unwrap();

    let subscriber = registry.with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}