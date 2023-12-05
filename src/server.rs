use crate::config::ServerConfig;
use crate::interface::Interface;
use crate::server::tunnel::QuincyTunnel;
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tracing::error;

pub mod address_pool;
pub mod connection;
pub mod tunnel;

/// Represents a Quincy server with multiple underlying Quincy tunnels.
pub struct QuincyServer {
    active_tunnels: Vec<QuincyTunnel>,
}

impl QuincyServer {
    /// Creates a new instance of a Quincy server.
    ///
    /// ### Arguments
    /// - `config` - the configuration for the server
    pub fn new(config: ServerConfig) -> Result<Self> {
        let tunnels = config
            .tunnels
            .into_iter()
            .flat_map(|(name, tunnel_config)| {
                QuincyTunnel::new(name, tunnel_config, &config.connection)
            })
            .collect();

        Ok(Self {
            active_tunnels: tunnels,
        })
    }

    /// Starts the Quincy server and all of its underlying tunnels.
    pub async fn run<I: Interface>(self) -> Result<()> {
        let mut tunnel_tasks = self
            .active_tunnels
            .into_iter()
            .map(|tunnel| tokio::spawn(tunnel.run::<I>()))
            .collect::<FuturesUnordered<_>>();

        loop {
            let (tunnel, task_result) = match tunnel_tasks.next().await {
                Some(tunnel) => tunnel??,
                None => return Err(anyhow!("No tunnels are running")),
            };

            error!(
                "Tunnel {} has encountered an error: {:?}",
                tunnel.name,
                task_result.expect_err("Tunnel task always returns an error")
            );

            tunnel_tasks.push(tokio::spawn(tunnel.run::<I>()));
        }
    }
}
