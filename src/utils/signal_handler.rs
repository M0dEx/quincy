use anyhow::{anyhow, Result};
use tokio::signal;

pub(crate) async fn handle_ctrl_c() -> Result<()> {
    signal::ctrl_c().await?;

    Err(anyhow!("Received stop signal"))
}
