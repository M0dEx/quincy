use anyhow::Result;
use clap::Parser;
use quincy::cli::Args;
use quincy::config::{FromPath, ServerConfig};
use quincy::server::QuincyServer;
use quincy::utils::enable_tracing;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = Args::parse();

    let config = ServerConfig::from_path(&args.config_path, &args.env_prefix)?;
    enable_tracing(&config.log.level);

    let mut server = QuincyServer::new(config).await?;
    server.run().await
}
