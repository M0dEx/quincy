use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::user::{load_users_file, UserDatabase};
use crate::config::{ConnectionConfig, TunnelConfig};
use crate::server::address_pool::AddressPool;
use crate::server::connection::QuincyConnection;
use crate::utils::socket::bind_socket;
use crate::utils::tasks::join_or_abort_task;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use etherparse::{IpHeader, PacketHeaders};
use ipnet::Ipv4Net;
use quinn::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::constants::{CLEANUP_INTERVAL, QUINN_RUNTIME};
use crate::interface::{Interface, InterfaceRead, InterfaceWrite};
use tracing::{debug, error, info, warn};

type SharedConnections = Arc<DashMap<IpAddr, QuincyConnection>>;

/// Represents a Quincy tunnel encapsulating Quincy connections and TUN interface IO.
pub struct QuincyTunnel {
    name: String,
    tunnel_config: TunnelConfig,
    connection_config: ConnectionConfig,
    active_connections: SharedConnections,
    user_database: Arc<UserDatabase>,
    address_pool: Arc<AddressPool>,
    buffer_size: usize,
    tasks: Vec<JoinHandle<Result<()>>>,
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
            active_connections: Arc::new(DashMap::new()),
            user_database: Arc::new(user_database),
            address_pool: Arc::new(address_pool),
            buffer_size: connection_config.mtu as usize,
            tasks: Vec::new(),
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn start<I: Interface>(&mut self) -> Result<()> {
        if self.is_ok() {
            return Err(anyhow!("Tunnel '{}' is already running", self.name));
        }

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

        self.tasks.push(tokio::spawn(Self::process_outbound_traffic(
            tun_read,
            self.active_connections.clone(),
            self.buffer_size,
        )));

        self.tasks.push(tokio::spawn(Self::process_inbound_traffic(
            tun_write, receiver,
        )));

        self.tasks.push(tokio::spawn(Self::cleanup_connections(
            self.active_connections.clone(),
            self.address_pool.clone(),
        )));

        self.tasks
            .push(tokio::spawn(Self::handle_incoming_connections(
                self.active_connections.clone(),
                self.connection_config.clone(),
                self.address_pool.clone(),
                Arc::new(sender),
                self.user_database.clone(),
                endpoint,
            )));

        Ok(())
    }

    /// Stops the tasks for this instance of Quincy tunnel.
    pub async fn stop(&mut self) -> Result<()> {
        let timeout = Duration::from_secs(1);

        self.active_connections.clear();
        self.address_pool.reset();

        while let Some(task) = self.tasks.pop() {
            if let Some(Err(e)) = join_or_abort_task(task, timeout).await {
                error!("An error occurred in tunnel '{}': {e}", self.name);
            }
        }

        Ok(())
    }

    /// Checks whether this instance of Quincy tunnel is running.
    ///
    /// ### Returns
    /// - `true` if all tunnel tasks are running, `false` if not
    pub fn is_ok(&self) -> bool {
        !self.tasks.is_empty() && self.tasks.iter().all(|task| !task.is_finished())
    }

    /// Cleans up stale (failed/timed out) connections.
    ///
    /// ### Arguments
    /// - `connections` - a map of connections and their associated client IP addresses
    /// - `address_pool` - the address pool being used
    async fn cleanup_connections(
        connections: SharedConnections,
        address_pool: Arc<AddressPool>,
    ) -> Result<()> {
        debug!("Started tunnel connection cleanup worker");

        loop {
            let mut stale_connections = vec![];

            for connection in connections.iter() {
                if !connection.value().is_ok() {
                    stale_connections.push(connection.key().to_owned());
                }
            }

            for connection_addr in stale_connections {
                warn!(
                    "Deactivating stale connection for client: {}",
                    connection_addr
                );
                let (_, mut connection) = connections
                    .remove(&connection_addr)
                    .expect("Stale connection exists");

                connection.stop().await?;
                address_pool.release_address(connection_addr);
            }

            sleep(CLEANUP_INTERVAL).await;
        }
    }

    /// Handles incoming connections by spawning a new QuincyConnection instance for them.
    ///
    /// ### Arguments
    /// - `active_connections` - a map of connections and their associated client IP addresses
    /// - `connection_config` - the connection configuration
    /// - `address_pool` - the address pool being used
    /// - `write_queue_sender` - the channel for sending data to the TUN interface worker
    /// - `user_database` - the user database
    /// - `endpoint` - the QUIC endpoint
    async fn handle_incoming_connections(
        active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
        connection_config: ConnectionConfig,
        address_pool: Arc<AddressPool>,
        write_queue_sender: Arc<UnboundedSender<Bytes>>,
        user_database: Arc<UserDatabase>,
        endpoint: Endpoint,
    ) -> Result<()> {
        info!(
            "Listening for incoming connections: {}",
            endpoint.local_addr().expect("Endpoint has a local address")
        );

        while let Some(handshake) = endpoint.accept().await {
            debug!(
                "Received incoming connection from '{}'",
                handshake.remote_address().ip()
            );

            let client_tun_ip = address_pool
                .next_available_address()
                .ok_or_else(|| anyhow!("Could not find an available address for client"))?;

            let mut connection = QuincyConnection::new(
                handshake.await?,
                &connection_config,
                write_queue_sender.clone(),
                user_database.clone(),
                client_tun_ip,
            );

            let connection = match connection.start().await {
                Ok(_) => connection,
                Err(e) => {
                    error!(
                        "Failed to set up connection with client '{client_tun_ip}': {e}",
                        client_tun_ip = client_tun_ip.addr(),
                        e = e
                    );
                    continue;
                }
            };

            info!(
                "Connection established: {client_tun_ip} ({})",
                connection.remote_address(),
            );

            active_connections.insert(client_tun_ip.addr(), connection);
        }

        Ok(())
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
    /// - `active_connections` - a map of connections and their associated client IP addresses
    /// - `buffer_size` - the size of the buffer to use when reading from the TUN interface
    async fn process_outbound_traffic(
        mut tun_read: impl InterfaceRead,
        active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
        buffer_size: usize,
    ) -> Result<()> {
        debug!("Started outbound traffic task (interface -> QUIC tunnel)");

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

            let connection = match active_connections.get(&dest_addr) {
                Some(connection) => connection,
                None => continue,
            };
            debug!("Found connection for IP {dest_addr}");

            let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
                anyhow!(
                    "Client {} failed to provide maximum datagram size",
                    connection.remote_address()
                )
            })?;

            if buf.len() > max_datagram_size {
                warn!(
                    "Dropping packet of size {} due to maximum datagram size being {}",
                    buf.len(),
                    max_datagram_size
                );
                continue;
            }

            debug!("Quinn MTU: {max_datagram_size}");

            connection.send_datagram(buf).await?;
        }
    }

    /// Reads data from the QUIC connection and sends it to the TUN interface worker.
    ///
    /// ### Arguments
    /// - `tun_write` - the write half of the TUN interface
    /// - `write_queue_receiver` - the channel for sending data to the TUN interface worker
    async fn process_inbound_traffic(
        mut tun_write: impl InterfaceWrite,
        mut write_queue_receiver: UnboundedReceiver<Bytes>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (QUIC tunnel -> interface)");

        while let Some(buf) = write_queue_receiver.recv().await {
            debug!("Sent {} bytes to tunnel", buf.len());
            tun_write.write_packet(buf).await?;
            debug!("Done");
        }

        Ok(())
    }
}
