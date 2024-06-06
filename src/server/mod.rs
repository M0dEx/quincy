pub mod address_pool;
mod connection;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::auth::server::AuthServer;
use crate::config::ServerConfig;
use crate::server::connection::QuincyConnection;
use crate::utils::signal_handler::handle_ctrl_c;
use crate::utils::socket::bind_socket;
use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::Ipv4Net;
use quinn::{Endpoint, VarInt};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::constants::{PACKET_BUFFER_SIZE, PACKET_CHANNEL_SIZE, QUINN_RUNTIME};
use crate::interface::{Interface, InterfaceRead, InterfaceWrite, Packet};
use crate::utils::tasks::abort_all;
use tracing::{debug, info, warn};

use self::address_pool::AddressPool;

type ConnectionQueues = Arc<DashMap<IpAddr, Sender<Bytes>>>;

/// Represents a Quincy server encapsulating Quincy connections and TUN interface IO.
pub struct QuincyServer {
    config: ServerConfig,
    connection_queues: ConnectionQueues,
    address_pool: Arc<AddressPool>,
}

impl QuincyServer {
    /// Creates a new instance of the Quincy tunnel.
    ///
    /// ### Arguments
    /// - `config` - the server configuration
    pub fn new(config: ServerConfig) -> Result<Self> {
        let interface_address = Ipv4Net::with_netmask(config.address_tunnel, config.address_mask)
            .context("invalid interface address or mask")?;

        let address_pool = AddressPool::new(interface_address.into());

        Ok(Self {
            config,
            connection_queues: Arc::new(DashMap::new()),
            address_pool: Arc::new(address_pool),
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn run<I: Interface>(&self) -> Result<()> {
        let interface_address =
            Ipv4Net::with_netmask(self.config.address_tunnel, self.config.address_mask)?.into();

        let interface = I::create(interface_address, self.config.connection.mtu)?;
        let auth_server = AuthServer::new(
            self.config.authentication.clone(),
            self.address_pool.clone(),
            self.config.connection.connection_timeout,
        )?;

        let (tun_read, tun_write) = interface.split();
        let (sender, receiver) = channel(PACKET_CHANNEL_SIZE);

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outbound_traffic(
                tun_read,
                self.connection_queues.clone(),
                self.config.connection.mtu as usize,
            )),
            tokio::spawn(Self::process_inbound_traffic(
                self.connection_queues.clone(),
                tun_write,
                receiver,
                self.config.isolate_clients,
            )),
        ]);

        let handler_task = self.handle_connections(auth_server, sender);

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
    /// - `auth_server` - the authentication server to use for authenticating clients
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    async fn handle_connections(
        &self,
        auth_server: AuthServer,
        ingress_queue: Sender<Packet>,
    ) -> Result<()> {
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
                    let client_ip = handshake.remote_address().ip();

                    debug!(
                        "Received incoming connection from '{}'",
                        client_ip
                    );

                    let quic_connection = match handshake.await {
                        Ok(connection) => connection,
                        Err(e) => {
                            warn!("Connection handshake with client '{client_ip}' failed: {e}");
                            continue;
                        }
                    };

                    let connection = QuincyConnection::new(
                        quic_connection,
                        ingress_queue.clone(),
                    );

                    authentication_tasks.push(
                        connection.authenticate(&auth_server)
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
                    let (connection_sender, connection_receiver) = channel(PACKET_CHANNEL_SIZE);

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
            let packet = tun_read.read_packet(buffer_size).await?;
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            debug!("Destination address for packet: {dest_addr}");

            let connection_queue = match connection_queues.get(&dest_addr) {
                Some(connection_queue) => connection_queue,
                None => continue,
            };

            debug!("Found connection for IP {dest_addr}");

            connection_queue.send(packet.into()).await?;
        }
    }

    /// Reads data from the QUIC connection and sends it to the TUN interface worker.
    ///
    /// ### Arguments
    /// - `connection_queues` - the queues for sending data to the QUIC connections
    /// - `tun_write` - the write half of the TUN interface
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    /// - `isolate_clients` - whether to isolate clients from each other
    async fn process_inbound_traffic(
        connection_queues: ConnectionQueues,
        tun_write: impl InterfaceWrite,
        ingress_queue: Receiver<Packet>,
        isolate_clients: bool,
    ) -> Result<()> {
        debug!("Started tunnel inbound traffic task (tunnel queue -> interface)");

        if isolate_clients {
            relay_isolated(connection_queues, tun_write, ingress_queue).await
        } else {
            relay_unisolated(connection_queues, tun_write, ingress_queue).await
        }
    }
}

#[inline]
async fn relay_isolated(
    connection_queues: ConnectionQueues,
    mut tun_write: impl InterfaceWrite,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

    loop {
        packets.clear();
        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        for packet in &packets {
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            if connection_queues.contains_key(&dest_addr) {
                // Drop the packet if the destination is a known client
                continue;
            }

            tun_write.write_packet(packet).await?;
        }
    }
}

#[inline]
async fn relay_unisolated(
    connection_queues: ConnectionQueues,
    mut tun_write: impl InterfaceWrite,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

    loop {
        packets.clear();
        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        for packet in &packets {
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            match connection_queues.get(&dest_addr) {
                // Send the packet to the appropriate QUIC connection
                Some(connection_queue) => connection_queue.send(packet.clone().into()).await?,
                // Send the packet to the TUN interface
                None => tun_write.write_packet(packet).await?,
            }
        }
    }
}
