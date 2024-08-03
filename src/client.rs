use crate::auth::client::AuthClient;

use crate::config::ClientConfig;
use crate::constants::{PACKET_BUFFER_SIZE, PACKET_CHANNEL_SIZE, QUINN_RUNTIME};
use crate::socket::bind_socket;
use crate::utils::signal_handler::handle_ctrl_c;
use crate::utils::tasks::abort_all;
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint, VarInt};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::network::dns::{add_dns_servers, delete_dns_servers};
use crate::network::interface::{Interface, InterfaceRead, InterfaceWrite};
use crate::network::packet::Packet;
use crate::network::route::add_routes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, info};

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient {
    config: ClientConfig,
}

impl QuincyClient {
    /// Creates a new instance of a Quincy client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Connects to the Quincy server and starts the workers for this instance of the Quincy client.
    pub async fn run<I: Interface>(&self) -> Result<()> {
        let connection = self.connect_to_server().await?;
        let auth_client = AuthClient::new(
            &self.config.authentication,
            self.config.connection.connection_timeout,
        )?;

        let (client_address, server_address) = auth_client.authenticate(&connection).await?;

        info!("Successfully authenticated");
        info!("Received client address: {client_address}");
        info!("Received server address: {server_address}");

        let mtu = self.config.connection.mtu;
        let interface = I::create(client_address, mtu)?;
        let interface_name = interface.name()?;

        info!("Created interface: {interface_name}");

        let routes = &self.config.network.routes;
        let dns_servers = &self.config.network.dns_servers;

        if !routes.is_empty() {
            add_routes(routes, &server_address.addr())?;
            for route in routes {
                info!("Added route: {route}");
            }
        }

        if !dns_servers.is_empty() {
            add_dns_servers(dns_servers, &interface_name)?;
            for dns_server in dns_servers {
                info!("Added DNS server: {dns_server}");
            }
        }

        let relay_result = self
            .relay_packets(connection, interface, mtu as usize)
            .await;

        if !dns_servers.is_empty() {
            delete_dns_servers()?;
        }

        relay_result
    }

    /// Connects to the Quincy server.
    ///
    /// ### Returns
    /// - `Connection` - a Quinn connection representing the connection to the Quincy server
    async fn connect_to_server(&self) -> Result<Connection> {
        let quinn_config = self.config.as_quinn_client_config()?;

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

    /// Relays packets between the TUN interface and the Quincy clients.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - the TUN interface
    /// - `interface_mtu` - the MTU of the TUN interface
    async fn relay_packets(
        &self,
        connection: Connection,
        interface: impl Interface,
        interface_mtu: usize,
    ) -> Result<()> {
        let connection = Arc::new(connection);
        let (tun_queue_send, tun_queue_recv) = channel(PACKET_CHANNEL_SIZE);
        let (tun_read, tun_write) = interface.split();

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_inbound_traffic(
                connection.clone(),
                tun_queue_send,
            )),
            tokio::spawn(Self::process_tun_queue(tun_queue_recv, tun_write)),
            tokio::spawn(Self::process_outgoing_traffic(
                connection.clone(),
                tun_read,
                interface_mtu,
            )),
        ]);

        let result = tokio::select! {
            Some(task_result) = tasks.next() => task_result?,
            signal_res = handle_ctrl_c() => {
                info!("Received shutdown signal, shutting down");
                signal_res
            },
        };

        // Stop all running tasks
        let _ = abort_all(tasks).await;

        // Close the QUIC connection
        connection.close(VarInt::from_u32(0x01), "Client shutdown".as_bytes());

        result
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
            let packet = read_interface.read_packet(interface_mtu).await?;

            connection.send_datagram(packet.into())?;
        }
    }

    /// Handles incoming packets from the Quincy clients and relays them to the TUN interface.
    ///
    /// ### Arguments
    /// - `tun_queue` - the TUN queue
    /// - `tun_write` - the write half of the TUN interface
    async fn process_tun_queue(
        mut tun_queue: Receiver<Packet>,
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

    /// Handles incoming packets from the Quincy server and relays them to the TUN interface queue.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `tun_queue` - the TUN queue
    async fn process_inbound_traffic(
        connection: Arc<Connection>,
        tun_queue: Sender<Packet>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (QUIC tunnel -> interface)");

        loop {
            let packet = connection.read_datagram().await?.into();

            tun_queue.send(packet).await?;
        }
    }
}
