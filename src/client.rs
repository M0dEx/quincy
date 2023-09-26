use crate::auth::client::AuthClient;

use crate::config::ClientConfig;
use crate::constants::QUINN_RUNTIME;
use crate::utils::socket::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint};

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use crate::utils::interface::{read_from_interface, set_up_interface, write_to_interface};
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tracing::{debug, info, warn};
use tun::AsyncDevice;

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient {
    client_config: ClientConfig,
}

impl QuincyClient {
    /// Creates a new instance of a Quincy client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(client_config: ClientConfig) -> Self {
        Self { client_config }
    }

    /// Connects to the Quincy server and starts the workers for this instance of the Quincy client.
    pub async fn run(&self) -> Result<()> {
        let connection = self.connect_to_server().await?;
        let mut auth_client =
            AuthClient::new(&connection, &self.client_config.authentication).await?;

        let assigned_address = auth_client.authenticate().await?;

        info!("Received client address: {assigned_address}");

        let interface = set_up_interface(assigned_address, self.client_config.connection.mtu)?;

        self.relay_packets(
            connection,
            interface,
            self.client_config.connection.mtu as usize,
        )
        .await?;

        Ok(())
    }

    /// Connects to the Quincy server.
    ///
    /// ### Returns
    /// - `Connection` - a Quinn connection representing the connection to the Quincy server
    async fn connect_to_server(&self) -> Result<Connection> {
        let quinn_config = self.client_config.as_quinn_client_config()?;
        let endpoint = self.create_quinn_endpoint()?;

        let server_hostname = self
            .client_config
            .connection_string
            .split(':')
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Could not parse hostname from connection string '{}'",
                    self.client_config.connection_string
                )
            })?;

        let server_addr = self
            .client_config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Connection string '{}' is invalid",
                    self.client_config.connection_string
                )
            })?;

        info!("Connecting: {}", self.client_config.connection_string);

        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;

        info!(
            "Connection established: {}",
            self.client_config.connection_string
        );

        Ok(connection)
    }

    /// Creates a Quinn endpoint.
    ///
    /// ### Returns
    /// - `Endpoint` - the Quinn endpoint
    fn create_quinn_endpoint(&self) -> Result<Endpoint> {
        let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        debug!("QUIC socket local address: {:?}", bind_addr);

        let socket = bind_socket(
            bind_addr,
            self.client_config.connection.send_buffer_size as usize,
            self.client_config.connection.recv_buffer_size as usize,
        )?;

        let endpoint_config = self.client_config.connection.as_endpoint_config()?;
        let endpoint = Endpoint::new(endpoint_config, None, socket, QUINN_RUNTIME.clone())?;

        Ok(endpoint)
    }

    /// Relays packets between the TUN interface and the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - the TUN interface
    async fn relay_packets(
        &self,
        connection: Connection,
        interface: AsyncDevice,
        interface_mtu: usize,
    ) -> Result<()> {
        let connection = Arc::new(connection);
        let (read, write) = tokio::io::split(interface);

        let inbound_task = tokio::spawn(Self::process_inbound_traffic(connection.clone(), write));
        let outgoing_task = tokio::spawn(Self::process_outgoing_traffic(
            connection.clone(),
            read,
            interface_mtu,
        ));

        tokio::select! {
            inbound_result = inbound_task => {
                inbound_result??;
            }
            outgoing_result = outgoing_task => {
                outgoing_result??;
            }
        }

        Ok(())
    }

    /// Handles incoming packets from the TUN interface and relays them to the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `read_interface` - the read half of the TUN interface
    /// - `interface_mtu` - the MTU of the TUN interface
    async fn process_outgoing_traffic(
        connection: Arc<Connection>,
        mut read_interface: ReadHalf<AsyncDevice>,
        interface_mtu: usize,
    ) -> Result<()> {
        debug!("Started outgoing traffic task (interface -> QUIC tunnel)");

        loop {
            let data = read_from_interface(&mut read_interface, interface_mtu).await?;

            let quinn_mtu = connection
                .max_datagram_size()
                .ok_or_else(|| anyhow!("The Quincy server does not support datagram transfer"))?;

            if data.len() > quinn_mtu {
                warn!(
                    "Dropping packet of size {} due to maximum datagram size being {}",
                    data.len(),
                    quinn_mtu
                );
                continue;
            }

            debug!(
                "Sending {} bytes to {:?}",
                data.len(),
                connection.remote_address()
            );

            connection.send_datagram(data)?;
        }
    }

    /// Handles incoming packets from the Quincy server and relays them to the TUN interface.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `write_interface` - the write half of the TUN interface
    async fn process_inbound_traffic(
        connection: Arc<Connection>,
        mut write_interface: WriteHalf<AsyncDevice>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (QUIC tunnel -> interface)");

        loop {
            let data = connection.read_datagram().await?;

            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            write_to_interface(&mut write_interface, data).await?;
        }
    }
}
