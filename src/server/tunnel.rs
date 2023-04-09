use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::Auth;
use crate::config::{ConnectionConfig, TunnelConfig};
use crate::server::address_pool::AddressPool;
use crate::server::connection::QuincyConnection;
use crate::utils::interface::{read_from_interface, set_up_interface, write_to_interface};
use crate::utils::socket::bind_socket;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use etherparse::{IpHeader, PacketHeaders};
use ipnet::Ipv4Net;
use quinn::{Connection, Endpoint};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use tun::AsyncDevice;

type SharedReadHalf<T> = Arc<RwLock<ReadHalf<T>>>;
type SharedWriteHalf<T> = Arc<RwLock<WriteHalf<T>>>;
type SharedSender<T> = Arc<UnboundedSender<T>>;
type SharedReceiver<T> = Arc<RwLock<UnboundedReceiver<T>>>;

pub struct QuincyTunnel {
    tun_config: TunnelConfig,
    connection_config: ConnectionConfig,
    tun_read: SharedReadHalf<AsyncDevice>,
    tun_write: SharedWriteHalf<AsyncDevice>,
    write_queue_sender: SharedSender<Bytes>,
    write_queue_receiver: SharedReceiver<Bytes>,
    active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
    buffer_size: usize,
    reader_task: Option<JoinHandle<Result<()>>>,
    writer_task: Option<JoinHandle<Result<()>>>,
    cleanup_task: Option<JoinHandle<Result<()>>>,
    auth: Arc<Auth>,
    address_pool: Arc<AddressPool>,
}

impl QuincyTunnel {
    pub fn new(tunnel_config: TunnelConfig, connection_config: &ConnectionConfig) -> Result<Self> {
        let interface_address =
            Ipv4Net::with_netmask(tunnel_config.address_server, tunnel_config.address_mask)?.into();

        let interface = set_up_interface(interface_address, connection_config.mtu)?;

        let buffer_size = connection_config.mtu as i32;
        let (tun_read, tun_write) = tokio::io::split(interface);
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let auth = Auth::new(Auth::load_users_file(&tunnel_config.users_file)?);
        let address_pool = AddressPool::new(interface_address)?;

        Ok(Self {
            tun_config: tunnel_config,
            connection_config: connection_config.clone(),
            tun_read: Arc::new(RwLock::new(tun_read)),
            tun_write: Arc::new(RwLock::new(tun_write)),
            write_queue_sender: Arc::new(sender),
            write_queue_receiver: Arc::new(RwLock::new(receiver)),
            active_connections: Arc::new(DashMap::new()),
            buffer_size: buffer_size as usize,
            reader_task: None,
            writer_task: None,
            cleanup_task: None,
            auth: Arc::new(auth),
            address_pool: Arc::new(address_pool),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.reader_task.is_some() || self.writer_task.is_some() {
            return Err(anyhow!("There is already a reader job active"));
        }

        self.reader_task = Some(tokio::spawn(Self::process_incoming_data(
            self.tun_read.clone(),
            self.active_connections.clone(),
            self.buffer_size,
        )));
        self.writer_task = Some(tokio::spawn(Self::process_outgoing_data(
            self.tun_write.clone(),
            self.write_queue_receiver.clone(),
        )));
        self.cleanup_task = Some(tokio::spawn(Self::cleanup_connections(
            self.active_connections.clone(),
            self.address_pool.clone(),
        )));

        let quinn_configuration = self
            .tun_config
            .as_quinn_server_config(&self.connection_config)?;
        let endpoint = self.create_quinn_endpoint(quinn_configuration)?;

        info!("Listening on {}", endpoint.local_addr().unwrap());

        while let Some(handshake) = endpoint.accept().await {
            self.handle_incoming_connection(handshake.await?).await?;
        }

        Ok(())
    }

    async fn cleanup_connections(
        connections: Arc<DashMap<IpAddr, QuincyConnection>>,
        address_pool: Arc<AddressPool>,
    ) -> Result<()> {
        let cleanup_interval = Duration::from_secs(1);

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

                connection.stop_workers().await?;
                address_pool.release_address(connection_addr);
            }

            sleep(cleanup_interval).await;
        }
    }

    async fn handle_incoming_connection(&self, connection: Connection) -> Result<()> {
        debug!(
            "Received incoming connection from {}",
            connection.remote_address().ip()
        );

        let client_tun_ip = self
            .address_pool
            .next_available_address()
            .ok_or_else(|| anyhow!("Could not find an available address for client"))?;

        let mut connection = QuincyConnection::new(
            connection,
            self.write_queue_sender.clone(),
            self.auth.clone(),
            self.tun_config.auth_timeout,
            client_tun_ip,
        );
        connection.start_worker()?;
        debug!("Started connection worker for client {client_tun_ip}");

        self.active_connections
            .insert(client_tun_ip.addr(), connection);

        Ok(())
    }

    fn create_quinn_endpoint(&self, quinn_config: quinn::ServerConfig) -> Result<Endpoint> {
        let socket = bind_socket(
            SocketAddr::V4(SocketAddrV4::new(
                self.tun_config.bind_address,
                self.tun_config.bind_port,
            )),
            self.connection_config.send_buffer_size as usize,
            self.connection_config.recv_buffer_size as usize,
        )?;

        let endpoint = Endpoint::new(
            Default::default(),
            Some(quinn_config),
            socket,
            quinn::TokioRuntime,
        )?;

        Ok(endpoint)
    }

    async fn process_incoming_data(
        tun_read: Arc<RwLock<ReadHalf<AsyncDevice>>>,
        active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
        buffer_size: usize,
    ) -> Result<()> {
        let mut tun_read = tun_read.write().await;

        debug!("Started incoming tunnel worker");
        loop {
            let buf = read_from_interface(&mut tun_read, buffer_size).await?;
            debug!(
                "Read {} bytes from TUN interface: {:?}",
                buf.len(),
                buf.iter().map(|byte| *byte as u32).collect::<Vec<u32>>()
            );

            let headers = match PacketHeaders::from_ip_slice(&buf) {
                Ok(headers) => headers,
                Err(e) => {
                    warn!("Failed to parse IP packet: {e}");
                    continue;
                }
            };
            debug!("Packet header: {:?}", headers);
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

            connection.send_datagram(buf)?;
        }
    }

    async fn process_outgoing_data(
        tun_write: Arc<RwLock<WriteHalf<AsyncDevice>>>,
        write_queue_receiver: Arc<RwLock<UnboundedReceiver<Bytes>>>,
    ) -> Result<()> {
        let mut tun_write = tun_write.write().await;
        let mut write_queue_receiver = write_queue_receiver.write().await;

        debug!("Started outgoing tunnel worker");
        while let Some(buf) = write_queue_receiver.recv().await {
            debug!("Sent {} bytes to tunnel", buf.len());
            write_to_interface(&mut tun_write, buf).await?;
        }

        Ok(())
    }
}
