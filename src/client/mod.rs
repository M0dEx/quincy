mod relayer;

use crate::auth::client::AuthClient;

use crate::config::ClientConfig;
use crate::constants::QUINN_RUNTIME;
use crate::socket::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::client::relayer::ClientRelayer;
use crate::network::interface::{Interface, InterfaceIO};
use tracing::{debug, info};

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient<I: InterfaceIO> {
    config: ClientConfig,
    relayer: Option<ClientRelayer<I>>,
}

impl<I: InterfaceIO> QuincyClient<I> {
    /// Creates a new instance of a Quincy client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            relayer: None,
        }
    }

    /// Connects to the Quincy server and starts the workers for this instance of the Quincy client.
    pub async fn start(&mut self) -> Result<()> {
        if self.relayer.is_some() {
            return Err(anyhow!("Client is already started"));
        }

        let connection = self.connect_to_server().await?;
        let auth_client = AuthClient::new(
            &self.config.authentication,
            self.config.connection.connection_timeout,
        )?;

        let (client_address, server_address) = auth_client.authenticate(&connection).await?;

        info!("Successfully authenticated");
        info!("Received client address: {client_address}");
        info!("Received server address: {server_address}");

        let interface = Interface::create(
            client_address,
            self.config.connection.mtu,
            Some(server_address.addr()),
            Some(self.config.network.routes.clone()),
            Some(self.config.network.dns_servers.clone()),
        )?;

        let relayer = ClientRelayer::start(interface, connection)?;
        self.relayer.replace(relayer);

        Ok(())
    }

    pub async fn wait_for_shutdown(&mut self) -> Result<()> {
        if let Some(relayer) = self.relayer.take() {
            relayer.wait_for_shutdown().await?;
        }

        Ok(())
    }

    /// Connects to the Quincy server.
    ///
    /// ### Returns
    /// - `Connection` - a Quinn connection representing the connection to the Quincy server
    async fn connect_to_server(&self) -> Result<Connection> {
        let quinn_config = self.config.quinn_client_config()?;

        let server_hostname = self
            .config
            .connection_string
            .split(':')
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Could not parse hostname from connection string '{}'",
                    self.config.connection_string
                )
            })?;

        let server_addr = self
            .config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Connection string '{}' is invalid",
                    self.config.connection_string
                )
            })?;

        info!("Connecting: {}", self.config.connection_string);

        let endpoint = self.create_quinn_endpoint(server_addr)?;
        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;

        info!("Connection established: {}", self.config.connection_string);

        Ok(connection)
    }

    /// Creates a Quinn endpoint.
    ///
    /// ### Arguments
    /// - `remote_address` - the remote address to connect to
    ///
    /// ### Returns
    /// - `Endpoint` - the Quinn endpoint
    fn create_quinn_endpoint(&self, remote_address: SocketAddr) -> Result<Endpoint> {
        let bind_addr: SocketAddr = SocketAddr::new(
            match remote_address.ip() {
                IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
                IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
            },
            0,
        );
        debug!("QUIC socket local address: {:?}", bind_addr);

        let socket = bind_socket(
            bind_addr,
            self.config.connection.send_buffer_size as usize,
            self.config.connection.recv_buffer_size as usize,
            false,
        )?;

        let endpoint_config = self.config.connection.as_endpoint_config()?;
        let endpoint = Endpoint::new(endpoint_config, None, socket, QUINN_RUNTIME.clone())?;

        Ok(endpoint)
    }
}
