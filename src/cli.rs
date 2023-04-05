use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg(long)]
    pub config_path: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}
