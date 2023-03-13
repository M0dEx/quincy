use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use crate::certificates::{load_certificates_from_file, load_private_key_from_file};
use crate::config::{ConnectionConfig, TunnelConfig};
use crate::connection::QuincyConnection;
use crate::constants::{
    QUIC_MTU_OVERHEAD, QUINCY_CIPHER_SUITES, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS,
};
use crate::utils::bind_socket;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use etherparse::{IpHeader, PacketHeaders};
use quinn::{Connection, Endpoint, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock;
use tokio::task;
use tokio::task::JoinHandle;
use tokio_tun::{Tun, TunBuilder};
use tracing::{debug, info, warn};

type SharedReadHalf<T> = Arc<RwLock<ReadHalf<T>>>;
type SharedWriteHalf<T> = Arc<RwLock<WriteHalf<T>>>;
type SharedSender<T> = Arc<UnboundedSender<T>>;
type SharedReceiver<T> = Arc<RwLock<UnboundedReceiver<T>>>;

pub struct QuincyTunnel {
    tun_config: TunnelConfig,
    connection_config: ConnectionConfig,
    tun_read: SharedReadHalf<Tun>,
    tun_write: SharedWriteHalf<Tun>,
    write_queue_sender: SharedSender<Bytes>,
    write_queue_receiver: SharedReceiver<Bytes>,
    active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
    buffer_size: usize,
    reader_task: Option<JoinHandle<Result<()>>>,
    writer_task: Option<JoinHandle<Result<()>>>,
}

impl QuincyTunnel {
    pub fn new(tunnel_config: TunnelConfig, connection_config: &ConnectionConfig) -> Result<Self> {
        let tun_interface = TunBuilder::new()
            .name("")
            .tap(false)
            .packet_info(false)
            .mtu(connection_config.mtu as i32)
            .up()
            .address(tunnel_config.address_server)
            .netmask(tunnel_config.address_mask)
            .try_build()
            .map_err(|e| anyhow!("Failed to create a TUN interface: {e}"))?;
        
        let buffer_size = connection_config.mtu as i32;
        let (tun_read, tun_write) = tokio::io::split(tun_interface);
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

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

        let quinn_configuration = self.quinn_configuration().await?;
        let endpoint = self.create_quinn_endpoint(quinn_configuration)?;

        info!("Listening on {}", endpoint.local_addr().unwrap());

        while let Some(handshake) = endpoint.accept().await {
            self.handle_incoming_connection(handshake.await?).await?;
        }

        Ok(())
    }

    async fn handle_incoming_connection(&self, connection: Connection) -> Result<()> {
        debug!(
            "Received incoming connection from {}",
            connection.remote_address().ip()
        );
        let mut address_stream = connection.open_uni().await?;

        let client_tun_ip = self.get_next_free_client_ip()?;

        // TODO: Move into auth module
        address_stream.write_u32(client_tun_ip.into()).await?;
        address_stream
            .write_u32(self.tun_config.address_mask.into())
            .await?;

        debug!("Sent address information to client {client_tun_ip}");

        let mut connection = QuincyConnection::new(connection, self.write_queue_sender.clone());
        connection.start_worker()?;
        debug!("Started connection worker for client {client_tun_ip}");

        self.active_connections
            .insert(IpAddr::V4(client_tun_ip), connection);

        Ok(())
    }

    async fn quinn_configuration(&self) -> Result<quinn::ServerConfig> {
        let certificate_file_path = self.tun_config.certificate_file.clone();
        let certificate_key_path = self.tun_config.certificate_key_file.clone();
        let key = task::spawn_blocking(move || load_private_key_from_file(&certificate_key_path)).await??;
        let certs = task::spawn_blocking(move || load_certificates_from_file(&certificate_file_path)).await??;

        let mut rustls_config = rustls::ServerConfig::builder()
            .with_cipher_suites(QUINCY_CIPHER_SUITES)
            .with_safe_default_kx_groups()
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        rustls_config.alpn_protocols = TLS_ALPN_PROTOCOLS.clone();

        let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(rustls_config));
        let mut transport_config = TransportConfig::default();

        // TODO: Investigate whether there could be a better solution
        transport_config.max_idle_timeout(None);
        transport_config
            .initial_max_udp_payload_size(self.connection_config.mtu as u16 + QUIC_MTU_OVERHEAD);

        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
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

    fn get_next_free_client_ip(&self) -> Result<Ipv4Addr> {
        // TODO: Take from a pool of available addresses
        let mut server_ip_bytes = self.tun_config.address_server.octets();
        server_ip_bytes[3] += 1_u8;

        Ok(Ipv4Addr::from(server_ip_bytes))
    }

    async fn process_incoming_data(
        tun_read: Arc<RwLock<ReadHalf<Tun>>>,
        active_connections: Arc<DashMap<IpAddr, QuincyConnection>>,
        buffer_size: usize,
    ) -> Result<()> {
        let mut tun_read = tun_read.write().await;

        debug!("Started incoming tunnel worker");
        loop {
            let mut buf = BytesMut::with_capacity(buffer_size);

            tun_read.read_buf(&mut buf).await?;
            debug!(
                "Read {} bytes from TUN interface: {:?}",
                buf.len(),
                buf.iter().map(|byte| *byte as u32).collect::<Vec<u32>>()
            );

            let headers = match PacketHeaders::from_ip_slice(&buf) {
                Ok(headers) => headers,
                Err(e) => {
                    warn!("Failed to parse IP packet: {e}");
                    continue
                }
            };
            debug!("Packet header: {:?}", headers);
            let ip_header = match headers.ip {
                Some(ip_header) => ip_header,
                None => {
                    warn!("Received a packet with invalid IP header");
                    continue
                },
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

            connection.send_datagram(buf.into())?;
        }
    }

    async fn process_outgoing_data(
        tun_write: Arc<RwLock<WriteHalf<Tun>>>,
        write_queue_receiver: Arc<RwLock<UnboundedReceiver<Bytes>>>,
    ) -> Result<()> {
        let mut tun_write = tun_write.write().await;
        let mut write_queue_receiver = write_queue_receiver.write().await;

        debug!("Started outgoing tunnel worker");
        while let Some(buf) = write_queue_receiver.recv().await {
            tun_write.write_all(&buf).await?;
        }

        Ok(())
    }
}
