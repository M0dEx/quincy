use std::sync::Arc;

use crate::config::ServerConfig;
use crate::server::tunnel::QuincyTunnel;
use anyhow::Result;
use dashmap::DashMap;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::RwLock;

pub mod address_pool;
pub mod connection;
pub mod tunnel;

pub struct QuincyServer {
    active_tunnels: DashMap<String, Arc<RwLock<QuincyTunnel>>>,
}

impl QuincyServer {
    pub async fn new(config: ServerConfig) -> Result<Self> {
        let tunnels = DashMap::new();

        for (name, tunnel_config) in config.tunnels.iter() {
            let tunnel = QuincyTunnel::new(tunnel_config.clone(), &config.connection)?;

            tunnels.insert(name.clone(), Arc::new(RwLock::new(tunnel)));
        }

        Ok(Self {
            active_tunnels: tunnels,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut futures = FuturesUnordered::new();

        for entry in self.active_tunnels.iter() {
            let tunnel = entry.value().clone();

            futures.push(tokio::spawn(
                async move { tunnel.write().await.run().await },
            ));
        }

        while let Some(tun_run) = futures.next().await {
            tun_run??;
        }

        Ok(())
    }
}
