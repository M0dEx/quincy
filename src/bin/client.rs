use anyhow::Result;
use clap::Parser;
use quincy::cli::Args;
use quincy::client::run_client;
use quincy::config::{ClientConfig, FromPath};
use quincy::utils::enable_tracing;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = Args::parse();

    let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
    enable_tracing(&config.log.level);

    run_client(config).await
}
