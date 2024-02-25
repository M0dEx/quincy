pub mod address_pool;
mod connection;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::auth::user::{load_users_file, UserDatabase};
use crate::config::ServerConfig;
use crate::server::connection::QuincyConnection;
use crate::utils::signal_handler::handle_ctrl_c;
use crate::utils::socket::bind_socket;
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use etherparse::{NetHeaders, PacketHeaders};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::Ipv4Net;
use quinn::{Endpoint, VarInt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::constants::{PACKET_BUFFER_SIZE, QUINN_RUNTIME};
use crate::interface::{Interface, InterfaceRead, InterfaceWrite};
use crate::utils::tasks::abort_all;
use tracing::{debug, info, warn};

use self::address_pool::AddressPool;

type ConnectionQueues = Arc<DashMap<IpAddr, UnboundedSender<Bytes>>>;

/// Represents a Quincy server encapsulating Quincy connections and TUN interface IO.
pub struct QuincyServer {
    config: ServerConfig,
    connection_queues: ConnectionQueues,
    user_database: UserDatabase,
    address_pool: AddressPool,
}

impl QuincyServer {
    /// Creates a new instance of the Quincy tunnel.
    ///
    /// ### Arguments
    /// - `config` - the server configuration
    pub fn new(config: ServerConfig) -> Result<Self> {
        let interface_address =
            Ipv4Net::with_netmask(config.address_tunnel, config.address_mask)?.into();

        let user_database = UserDatabase::new(load_users_file(&config.users_file)?);
        let address_pool = AddressPool::new(interface_address);

        Ok(Self {
            config,
            connection_queues: Arc::new(DashMap::new()),
            user_database,
            address_pool,
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn run<I: Interface>(self) -> Result<()> {
        let interface_address =
            Ipv4Net::with_netmask(self.config.address_tunnel, self.config.address_mask)?.into();
        let interface = I::create(interface_address, self.config.connection.mtu)?;

        let (tun_read, tun_write) = interface.split();
        let (sender, receiver) = mpsc::unbounded_channel();

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outbound_traffic(
                tun_read,
                self.connection_queues.clone(),
                self.config.connection.mtu as usize,
            )),
            tokio::spawn(Self::process_inbound_traffic(tun_write, receiver)),
        ]);

        let handler_task = self.handle_connections(sender);

        let result = tokio::select! {
            handler_task_result = handler_task => handler_task_result,
            Some(task_result) = tasks.next() => task_result?,
        };

        let _ = abort_all(tasks).await;

        result
    }

    /// Handles incoming connections by spawning a new QuincyConnection instance for them.
    ///
    /// ### Arguments
    /// - `ingress_queue` - the queue to send data to the TUN interface
    /// - `endpoint` - the QUIC endpoint
    async fn handle_connections(&self, ingress_queue: UnboundedSender<Bytes>) -> Result<()> {
        let endpoint = self.create_quinn_endpoint()?;

        info!(
            "Starting connection handler: {}",
            endpoint.local_addr().expect("Endpoint has a local address")
        );

        let mut authentication_tasks = FuturesUnordered::new();
        let mut connection_tasks = FuturesUnordered::new();

        loop {
            tokio::select! {
                // New connections
                Some(handshake) = endpoint.accept() => {
                    debug!(
                        "Received incoming connection from '{}'",
                        handshake.remote_address().ip()
                    );

                    let quic_connection = handshake.await?;

                    let connection = QuincyConnection::new(
                        quic_connection,
                        ingress_queue.clone(),
                    );

                    authentication_tasks.push(
                        connection.authenticate(&self.user_database, &self.address_pool, self.config.connection.timeout)
                    );
                }

                // Authentication tasks
                Some(connection) = authentication_tasks.next() => {
                    let connection = match connection {
                        Ok(connection) => connection,
                        Err(e) => {
                            warn!("Failed to authenticate client: {e}");
                            continue;
                        }
                    };

                    let client_address = connection.client_address()?.addr();
                    let (connection_sender, connection_receiver) = mpsc::unbounded_channel();

                    connection_tasks.push(tokio::spawn(connection.run(connection_receiver)));
                    self.connection_queues.insert(client_address, connection_sender);
                }

                // Connection tasks
                Some(connection) = connection_tasks.next() => {
                    let (connection, err) = connection?;
                    let client_address = &connection.client_address()?.addr();

                    self.connection_queues.remove(client_address);
                    self.address_pool.release_address(client_address);
                    warn!("Connection with client {client_address} has encountered an error: {err}");
                }

                // Shutdown
                signal_res = handle_ctrl_c() => {
                    info!("Received shutdown signal, shutting down");
                    let _ = abort_all(connection_tasks).await;

                    endpoint.close(VarInt::from_u32(0x01), "Server shutdown".as_bytes());

                    return signal_res;
                }
            }
        }
    }

    /// Creates a Quinn QUIC endpoint that clients can connect to.
    ///
    /// ### Arguments
    /// - `quinn_config` - the Quinn server configuration to use
    fn create_quinn_endpoint(&self) -> Result<Endpoint> {
        let quinn_config = self.config.as_quinn_server_config()?;

        let socket = bind_socket(
            SocketAddr::new(self.config.bind_address, self.config.bind_port),
            self.config.connection.send_buffer_size as usize,
            self.config.connection.recv_buffer_size as usize,
        )?;

        let endpoint_config = self.config.connection.as_endpoint_config()?;
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

            let net_header = match headers.net {
                Some(net) => net,
                None => {
                    warn!("Received a packet with invalid IP header");
                    continue;
                }
            };

            let dest_addr: IpAddr = match net_header {
                NetHeaders::Ipv4(header, _) => header.destination.into(),
                NetHeaders::Ipv6(header, _) => header.destination.into(),
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

        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

        loop {
            packets.clear();
            ingress_queue
                .recv_many(&mut packets, PACKET_BUFFER_SIZE)
                .await;

            tun_write.write_packets(&packets).await?;
        }
    }
}
