use crate::auth::client::AuthClient;

use crate::config::ClientConfig;
use crate::constants::{PACKET_BUFFER_SIZE, QUINN_RUNTIME};
use crate::utils::socket::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::interface::{Interface, InterfaceRead, InterfaceWrite};
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info};

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
    pub async fn run<I: Interface>(&self) -> Result<()> {
        let connection = self.connect_to_server().await?;
        let mut auth_client =
            AuthClient::new(&connection, &self.client_config.authentication).await?;

        let assigned_address = auth_client.authenticate().await?;

        info!("Successfully authenticated");
        info!("Received client address: {assigned_address}");

        let interface = I::create(assigned_address, self.client_config.connection.mtu)?;

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

        let endpoint = self.create_quinn_endpoint(server_addr)?;
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
        interface: impl Interface,
        interface_mtu: usize,
    ) -> Result<()> {
        let connection = Arc::new(connection);
        let (tun_queue_send, tun_queue_recv) = unbounded_channel();
        let (tun_read, tun_write) = tokio::io::split(interface);

        let mut client_tasks = FuturesUnordered::new();

        client_tasks.push(tokio::spawn(Self::process_inbound_traffic(
            connection.clone(),
            tun_queue_send,
        )));
        client_tasks.push(tokio::spawn(Self::process_tun_queue(
            tun_queue_recv,
            tun_write,
        )));
        client_tasks.push(tokio::spawn(Self::process_outgoing_traffic(
            connection.clone(),
            tun_read,
            interface_mtu,
        )));

        client_tasks
            .next()
            .await
            .expect("Client tasks are not empty")?
    }

    /// Handles incoming packets from the TUN interface and relays them to the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `read_interface` - the read half of the TUN interface
    /// - `interface_mtu` - the MTU of the TUN interface
    async fn process_outgoing_traffic(
        connection: Arc<Connection>,
        mut read_interface: impl InterfaceRead,
        interface_mtu: usize,
    ) -> Result<()> {
        debug!("Started outgoing traffic task (interface -> QUIC tunnel)");

        loop {
            let data = read_interface.read_packet(interface_mtu).await?;

            debug!(
                "Sending {} bytes to {:?}",
                data.len(),
                connection.remote_address()
            );

            connection.send_datagram(data)?;
        }
    }

    async fn process_tun_queue(
        mut tun_queue: UnboundedReceiver<Bytes>,
        mut tun_write: impl InterfaceWrite,
    ) -> Result<()> {
        debug!("Started TUN queue task (interface -> QUIC tunnel)");

        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

        loop {
            packets.clear();
            tun_queue.recv_many(&mut packets, PACKET_BUFFER_SIZE).await;

            tun_write.write_packets(&packets).await?;
        }
    }

    /// Handles incoming packets from the Quincy server and relays them to the TUN interface.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `write_interface` - the write half of the TUN interface
    async fn process_inbound_traffic(
        connection: Arc<Connection>,
        tun_queue: UnboundedSender<Bytes>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (QUIC tunnel -> interface)");

        loop {
            let data = connection.read_datagram().await?;

            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            tun_queue.send(data)?;
        }
    }
}
