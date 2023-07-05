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
use tokio::try_join;
use tracing::{debug, info};
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

        debug!("Received TUN address: {assigned_address}");

        let interface = set_up_interface(assigned_address, self.client_config.connection.mtu)?;

        try_join!(
            auth_client.maintain_session(),
            self.relay_packets(
                connection,
                interface,
                self.client_config.connection.mtu as usize
            ),
        )?;

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

        info!("Connecting to '{}'", self.client_config.connection_string);
        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;
        info!(
            "Connection to '{}' established",
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
        info!("Local address: {:?}", bind_addr);

        let socket = bind_socket(
            bind_addr,
            self.client_config.connection.send_buffer_size as usize,
            self.client_config.connection.recv_buffer_size as usize,
        )?;

        let endpoint = Endpoint::new(Default::default(), None, socket, QUINN_RUNTIME.clone())?;

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

        let (outbound_task, inbound_task) = try_join!(
            tokio::spawn(Self::process_outbound_traffic(
                connection.clone(),
                read,
                interface_mtu
            )),
            tokio::spawn(Self::process_inbound_traffic(
                connection.clone(),
                write,
                interface_mtu
            )),
        )?;

        inbound_task?;
        outbound_task?;

        Ok(())
    }

    /// Handles incoming packets from the TUN interface and relays them to the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `read_interface` - the read half of the TUN interface
    /// - `interface_mtu` - the MTU of the TUN interface
    async fn process_outbound_traffic(
        connection: Arc<Connection>,
        mut read_interface: ReadHalf<AsyncDevice>,
        interface_mtu: usize,
    ) -> Result<()> {
        debug!("Started send task");
        loop {
            let quinn_mtu = connection
                .max_datagram_size()
                .ok_or_else(|| anyhow!("The Quincy server does not support datagram transfer"))?;

            if interface_mtu > quinn_mtu {
                return Err(anyhow!(
                    "Interface MTU ({interface_mtu}) > QUIC tunnel MTU ({quinn_mtu})"
                ));
            }

            let data = read_from_interface(&mut read_interface, interface_mtu).await?;

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
        interface_mtu: usize,
    ) -> Result<()> {
        debug!("Started recv task");
        loop {
            let data = connection.read_datagram().await?;

            if data.len() > interface_mtu {
                return Err(anyhow!(
                    "Length of the data sent by the server ({}) > interface MTU ({interface_mtu})",
                    data.len()
                ));
            }

            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            write_to_interface(&mut write_interface, data).await?;
        }
    }
}
