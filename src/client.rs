use crate::config::{ClientConfig, ConnectionConfig};
use crate::connection::relay_packets;
use crate::utils::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Endpoint, TransportConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_tun::TunBuilder;
use tracing::{debug, error, info};
use rustls::{Certificate, RootCertStore};
use crate::certificates::load_certificates_from_file;
use crate::constants::{QUIC_MTU_OVERHEAD, QUINCY_CIPHER_SUITES, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS};


fn configure_quinn(config: &ClientConfig) -> Result<quinn::ClientConfig> {
    let trusted_certificates: Vec<Certificate> = config
        .authentication
        .trusted_certificates
        .iter()
        .filter_map(|cert_path| match load_certificates_from_file(cert_path) {
            Ok(certificates) => Some(certificates),
            Err(e) => {
                error!("Could not load certificates from {cert_path:?} due to an error: {e}");
                None
            }
        })
        .flatten()
        .collect();

    let mut cert_store = RootCertStore::empty();

    for certificate in trusted_certificates {
        cert_store.add(&certificate)?;
    }

    let mut rustls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(QUINCY_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
        .with_root_certificates(cert_store)
        .with_no_client_auth();

    rustls_config.alpn_protocols = TLS_ALPN_PROTOCOLS.clone();

    let mut quinn_config = quinn::ClientConfig::new(Arc::new(rustls_config));
    let mut transport_config = TransportConfig::default();

    // TODO: Investigate whether there could be a better solution
    // There is - the auth module
    transport_config.max_idle_timeout(None);
    transport_config.initial_max_udp_payload_size(config.connection.mtu as u16 + QUIC_MTU_OVERHEAD);

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

pub async fn run_client(config: ClientConfig) -> Result<()> {
    info!(
        "Connecting to: {:?}",
        config.connection_address
    );

    let quinn_config = configure_quinn(&config)?;
    let endpoint = create_quinn_endpoint(&config.connection)?;

    let connection = endpoint
        .connect_with(
            quinn_config,
            SocketAddr::from_str(&config.connection_address)?,
            // TODO: Un-hardcode hostname
            "quincy",
        )?
        .await?;

    info!(
        "Connection established: {:?}",
        config.connection_address
    );

    let mut address_stream = connection.accept_uni().await?;
    let ip = Ipv4Addr::from(address_stream.read_u32().await?);
    let mask = Ipv4Addr::from(address_stream.read_u32().await?);

    debug!("Received TUN IP address {} with mask {}", ip, mask,);

    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
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
