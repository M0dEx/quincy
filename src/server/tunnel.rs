use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::user::{load_users_file, UserDatabase};
use crate::config::{ConnectionConfig, TunnelConfig};
use crate::server::address_pool::AddressPool;
use crate::server::connection::QuincyConnection;
use crate::utils::socket::bind_socket;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use etherparse::{IpHeader, PacketHeaders};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::Ipv4Net;
use quinn::Endpoint;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::constants::QUINN_RUNTIME;
use crate::interface::{Interface, InterfaceRead, InterfaceWrite};
use crate::utils::tasks::join_or_abort_all;
use tracing::{debug, info, warn};

type ConnectionQueues = Arc<DashMap<IpAddr, UnboundedSender<Bytes>>>;

/// Represents a Quincy tunnel encapsulating Quincy connections and TUN interface IO.
pub struct QuincyTunnel {
    pub name: String,
    tunnel_config: TunnelConfig,
    connection_config: ConnectionConfig,
    connection_queues: ConnectionQueues,
    user_database: UserDatabase,
    address_pool: AddressPool,
    buffer_size: usize,
}

impl QuincyTunnel {
    /// Creates a new instance of the Quincy tunnel.
    ///
    /// ### Arguments
    /// = `name` - the name of the tunnel
    /// - `tunnel_config` - the tunnel configuration
    /// - `connection_config` - the connection configuration
    pub fn new(
        name: String,
        tunnel_config: TunnelConfig,
        connection_config: &ConnectionConfig,
    ) -> Result<Self> {
        let interface_address =
            Ipv4Net::with_netmask(tunnel_config.address_tunnel, tunnel_config.address_mask)?.into();

        let user_database = UserDatabase::new(load_users_file(&tunnel_config.users_file)?);
        let address_pool = AddressPool::new(interface_address)?;

        Ok(Self {
            name,
            tunnel_config,
            connection_config: connection_config.clone(),
            connection_queues: Arc::new(DashMap::new()),
            user_database,
            address_pool,
            buffer_size: connection_config.mtu as usize,
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn run<I: Interface>(self) -> Result<(Self, Result<()>)> {
        let interface_address = Ipv4Net::with_netmask(
            self.tunnel_config.address_tunnel,
            self.tunnel_config.address_mask,
        )?
        .into();
        let interface = I::create(interface_address, self.connection_config.mtu)?;

        let (tun_read, tun_write) = tokio::io::split(interface);
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let quinn_configuration = self
            .tunnel_config
            .as_quinn_server_config(&self.connection_config)?;
        let endpoint = self.create_quinn_endpoint(quinn_configuration)?;

        let mut tunnel_tasks = FuturesUnordered::new();

        tunnel_tasks.push(tokio::spawn(Self::process_outbound_traffic(
            tun_read,
            self.connection_queues.clone(),
            self.buffer_size,
        )));

        tunnel_tasks.push(tokio::spawn(Self::process_inbound_traffic(
            tun_write, receiver,
        )));

        let handler_task = self.handle_incoming_connections(sender, endpoint);

        let result = tokio::select! {
            handler_task_result = handler_task => handler_task_result,
            Some(task_result) = tunnel_tasks.next() => task_result?,
        };

        join_or_abort_all(tunnel_tasks, Duration::from_secs(1)).await?;

        Ok((self, result))
    }

    /// Handles incoming connections by spawning a new QuincyConnection instance for them.
    ///
    /// ### Arguments
    /// - `ingress_queue` - the queue to send data to the TUN interface
    /// - `endpoint` - the QUIC endpoint
    async fn handle_incoming_connections(
        &self,
        ingress_queue: UnboundedSender<Bytes>,
        endpoint: Endpoint,
    ) -> Result<()> {
        info!(
            "Listening for incoming connections: {}",
            endpoint.local_addr().expect("Endpoint has a local address")
        );

        let mut connection_tasks = FuturesUnordered::new();

        loop {
            tokio::select! {
                Some(handshake) = endpoint.accept() => {
                    debug!(
                        "Received incoming connection from '{}'",
                        handshake.remote_address().ip()
                    );

                    let client_tun_ip = self.address_pool
                        .next_available_address()
                        .ok_or_else(|| anyhow!("Could not find an available address for client"))?;

                    let quic_connection = Arc::new(handshake.await?);
                    let (connection_sender, connection_receiver) = mpsc::unbounded_channel();

                    let mut connection = QuincyConnection::new(
                        quic_connection.clone(),
                        client_tun_ip,
                        ingress_queue.clone(),
                    );

                    if let Err(e) = connection.authenticate(&self.user_database, self.connection_config.timeout).await {
                        warn!("Failed to authenticate client {client_tun_ip}: {e}");
                        self.address_pool.release_address(&client_tun_ip.addr());
                        continue;
                    }

                    connection_tasks.push(tokio::spawn(connection.run(connection_receiver)));
                    self.connection_queues.insert(client_tun_ip.addr(), connection_sender);
                }

                Some(connection) = connection_tasks.next() => {
                    let (connection, err) = connection?;
                    let client_address = &connection.client_address.addr();

                    self.connection_queues.remove(client_address);
                    self.address_pool.release_address(client_address);
                    warn!("Connection with client {client_address} has encountered an error: {err}");
                }
            }
        }
    }

    /// Creates a Quinn QUIC endpoint that clients can connect to.
    ///
    /// ### Arguments
    /// - `quinn_config` - the Quinn server configuration to use
    fn create_quinn_endpoint(&self, quinn_config: quinn::ServerConfig) -> Result<Endpoint> {
        let socket = bind_socket(
            SocketAddr::new(
                self.tunnel_config.bind_address,
                self.tunnel_config.bind_port,
            ),
            self.connection_config.send_buffer_size as usize,
            self.connection_config.recv_buffer_size as usize,
        )?;

        let endpoint_config = self.connection_config.as_endpoint_config()?;
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(quinn_config),
            socket,
            QUINN_RUNTIME.clone(),
        )?;

        Ok(endpoint)
    }

    /// Reads data from the TUN interface and sends it to the appropriate client.
    ///
    /// ### Arguments
    /// - `tun_read` - the read half of the TUN interface
    /// - `connection_queues` - the queues for sending data to the QUIC connections
    /// - `buffer_size` - the size of the buffer to use when reading from the TUN interface
    async fn process_outbound_traffic(
        mut tun_read: impl InterfaceRead,
        connection_queues: ConnectionQueues,
        buffer_size: usize,
    ) -> Result<()> {
        debug!("Started tunnel outbound traffic task (interface -> connection queue)");

        loop {
            let buf = tun_read.read_packet(buffer_size).await?;

            let headers = match PacketHeaders::from_ip_slice(&buf) {
                Ok(headers) => headers,
                Err(e) => {
                    warn!("Failed to parse IP packet: {e}");
                    continue;
                }
            };

            let ip_header = match headers.ip {
                Some(ip_header) => ip_header,
                None => {
                    warn!("Received a packet with invalid IP header");
                    continue;
                }
            };

            let dest_addr: IpAddr = match ip_header {
                IpHeader::Version4(header, _) => header.destination.into(),
                IpHeader::Version6(header, _) => header.destination.into(),
            };
            debug!("Destination address for packet: {dest_addr}");

            let connection_queue = match connection_queues.get(&dest_addr) {
                Some(connection_queue) => connection_queue,
                None => continue,
            };
            debug!("Found connection for IP {dest_addr}");

            connection_queue.send(buf)?;
        }
    }

    /// Reads data from the QUIC connection and sends it to the TUN interface worker.
    ///
    /// ### Arguments
    /// - `tun_write` - the write half of the TUN interface
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    async fn process_inbound_traffic(
        mut tun_write: impl InterfaceWrite,
        mut ingress_queue: UnboundedReceiver<Bytes>,
    ) -> Result<()> {
        debug!("Started tunnel inbound traffic task (tunnel queue -> interface)");

        while let Some(buf) = ingress_queue.recv().await {
            debug!("Sending {} bytes to tunnel", buf.len());
            tun_write.write_packet(buf).await?;
        }

        Ok(())
    }
}
