use anyhow::Result;
use clap::Parser;
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, FromPath};
use quincy::utils::cli::Args;
use quincy::utils::tracing::enable_tracing;
use tracing::error;

#[tokio::main]
async fn main() {
    let args: Args = Args::parse();

    match run_client(args).await {
        Ok(_) => {}
        Err(e) => error!("A critical error occurred: {e}"),
    }
}

async fn run_client(args: Args) -> Result<()> {
    let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
    enable_tracing(&config.log.level);

    let client = QuincyClient::new(config);
    client.run().await
}
