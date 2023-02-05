use crate::config::{Config, ConnectionConfig};
use crate::connection::relay_packets;
use crate::constants::{
    PERF_CIPHER_SUITES, QUIC_MTU_OVERHEAD, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS,
};
use crate::utils::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Endpoint, TransportConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_tun::TunBuilder;
use tracing::{debug, info};

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn configure_quinn(connection_config: &ConnectionConfig) -> Result<quinn::ClientConfig> {
    let mut rustls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
        // TODO: Get rid of this
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    rustls_config.alpn_protocols = TLS_ALPN_PROTOCOLS.clone();

    let mut quinn_config = quinn::ClientConfig::new(Arc::new(rustls_config));
    let mut transport_config = TransportConfig::default();

    // TODO: Investigate whether there could be a better solution
    transport_config.max_idle_timeout(None);
    transport_config.initial_max_udp_payload_size(connection_config.mtu as u16 + QUIC_MTU_OVERHEAD);

    quinn_config.transport_config(Arc::new(transport_config));

    Ok(quinn_config)
}

fn create_quinn_endpoint(connection_config: &ConnectionConfig) -> Result<Endpoint> {
    let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    info!("Local address: {:?}", bind_addr);

    let socket = bind_socket(
        bind_addr,
        connection_config.send_buffer_size as usize,
        connection_config.recv_buffer_size as usize,
    )?;

    let endpoint = Endpoint::new(Default::default(), None, socket, quinn::TokioRuntime)?;

    Ok(endpoint)
}

pub async fn run_client(config: Config) -> Result<()> {
    let client_config = config
        .client
        .ok_or_else(|| anyhow!("Config is validated and contains the client configuration."))?;
    info!("Connecting to: {:?}", client_config.connection_address);

    let quinn_config = configure_quinn(&config.connection)?;
    let endpoint = create_quinn_endpoint(&config.connection)?;

    let connection = endpoint
        .connect_with(
            quinn_config,
            SocketAddr::from_str(&client_config.connection_address)?,
            "localhost",
        )?
        .await?;

    info!(
        "Connection established: {:?}",
        client_config.connection_address
    );

    let mut address_stream = connection.accept_uni().await?;
    let ip = Ipv4Addr::from(address_stream.read_u32().await?);
    let mask = Ipv4Addr::from(address_stream.read_u32().await?);

    debug!("Received TUN IP address {} with mask {}", ip, mask,);

    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(true)
        .mtu(config.connection.mtu as i32)
        .up()
        .address(ip)
        .netmask(mask)
        .try_build()
        .map_err(|e| anyhow!("Failed to create a TUN interface: {e}"))?;

    debug!("Created a TUN interface");

    relay_packets(Arc::new(connection), tun, config.connection.mtu as usize).await?;

    Ok(())
}
