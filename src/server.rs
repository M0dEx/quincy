use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use crate::tun::make_tun;

use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint, TransportConfig};
use tokio_tun::Tun;
use tracing::info;
use crate::certificates::{load_certificates_from_file, load_private_key_from_file};
use crate::config::{Config, ConnectionConfig, ServerConfig};
use crate::connection::relay_packets;
use crate::constants::{PERF_CIPHER_SUITES, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS};
use crate::utils::bind_socket;

async fn configure_quinn(server_config: &ServerConfig, connection_config: &ConnectionConfig) -> Result<quinn::ServerConfig> {
    let key = load_private_key_from_file(server_config.certificate_key_file.clone()).await?;
    let certs = load_certificates_from_file(server_config.certificates_file.clone()).await?;

    let mut rustls_config = rustls::ServerConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    rustls_config.alpn_protocols = TLS_ALPN_PROTOCOLS.clone();

    let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(rustls_config));
    let mut transport_config = TransportConfig::default();

    // TODO: Investigate whether there could be a better solution
    transport_config.max_idle_timeout(None);
    transport_config.initial_max_udp_payload_size(connection_config.mtu);

    quinn_config.transport_config(Arc::new(transport_config));

    Ok(quinn_config)
}

fn create_quinn_endpoint(
    server_config: &ServerConfig,
    connection_config: &ConnectionConfig,
    quinn_config: quinn::ServerConfig
) -> Result<Endpoint> {
    let socket = bind_socket(
        SocketAddr::V4(SocketAddrV4::new(server_config.bind_address, server_config.bind_port)),
        connection_config.send_buffer_size as usize,
        connection_config.recv_buffer_size as usize,
    )?;

    let endpoint = Endpoint::new(
        Default::default(),
        Some(quinn_config),
        socket,
        quinn::TokioRuntime
    )?;

    Ok(endpoint)
}

pub async fn run_server(config: Config) -> Result<()> {
    let server_config = config.server.ok_or_else(|| anyhow!("Config is validated and contains the server configuration."))?;

    let quinn_configuration = configure_quinn(&server_config, &config.connection).await?;
    let endpoint = create_quinn_endpoint(&server_config, &config.connection, quinn_configuration)?;

    info!("Listening on {}", endpoint.local_addr().unwrap());

    let tun = make_tun(
        "".to_string(),
        "10.0.0.1".parse()?,
        "10.0.0.2".parse()?,
        1350
    )?;

    handle(endpoint.accept().await.ok_or_else(|| anyhow!("No connection"))?, tun, 1350).await?;

    Ok(())
}

async fn handle(handshake: quinn::Connecting, interface: Tun, mtu: usize) -> Result<()> {
    let connection: Connection = handshake.await?;
    info!("{:?} connected", connection.remote_address());

    relay_packets(Arc::new(connection), interface, mtu).await?;

    Ok(())
}
