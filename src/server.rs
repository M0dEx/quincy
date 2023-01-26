use crate::tun::{make_tun, TunWorker};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use crate::certificates::{load_certificates_from_file, load_private_key_from_file};
use crate::config::{Config, ConnectionConfig, ServerConfig};
use crate::connection::QuincyConnection;
use crate::constants::{PERF_CIPHER_SUITES, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS};
use crate::utils::bind_socket;
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint, TransportConfig};
use tokio::io::AsyncWriteExt;
use tracing::info;

async fn configure_quinn(
    server_config: &ServerConfig,
    connection_config: &ConnectionConfig,
) -> Result<quinn::ServerConfig> {
    let key = load_private_key_from_file(server_config.certificate_key_file.clone()).await?;
    let certs = load_certificates_from_file(server_config.certificate_file.clone()).await?;

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
    transport_config.initial_max_udp_payload_size(connection_config.mtu as u16);

    quinn_config.transport_config(Arc::new(transport_config));

    Ok(quinn_config)
}

fn create_quinn_endpoint(
    server_config: &ServerConfig,
    connection_config: &ConnectionConfig,
    quinn_config: quinn::ServerConfig,
) -> Result<Endpoint> {
    let socket = bind_socket(
        SocketAddr::V4(SocketAddrV4::new(
            server_config.bind_address,
            server_config.bind_port,
        )),
        connection_config.send_buffer_size as usize,
        connection_config.recv_buffer_size as usize,
    )?;

    let endpoint = Endpoint::new(
        Default::default(),
        Some(quinn_config),
        socket,
        quinn::TokioRuntime,
    )?;

    Ok(endpoint)
}

pub async fn run_server(config: Config) -> Result<()> {
    let server_config = config
        .server
        .ok_or_else(|| anyhow!("Config is validated and contains the server configuration."))?;

    let quinn_configuration = configure_quinn(&server_config, &config.connection).await?;
    let endpoint = create_quinn_endpoint(&server_config, &config.connection, quinn_configuration)?;

    info!("Listening on {}", endpoint.local_addr().unwrap());

    let tun = make_tun(
        "".to_string(),
        server_config.address_server,
        server_config.address_mask,
        config.connection.mtu,
    )?;

    let mut tun_worker = TunWorker::new(tun, config.connection.mtu as usize);
    tun_worker.start_workers().await?;

    while let Some(handshake) = endpoint.accept().await {
        let client_tun_ip = get_next_free_client_ip(server_config.address_server);
        let ip_mask = server_config.address_mask;

        handle_incoming_connection(&tun_worker, client_tun_ip, ip_mask, handshake.await?).await?;
    }

    Ok(())
}

async fn handle_incoming_connection(
    tun_worker: &TunWorker,
    client_tun_ip: Ipv4Addr,
    ip_mask: Ipv4Addr,
    connection: Connection,
) -> Result<()> {
    let mut address_stream = connection.open_uni().await?;

    address_stream.write_u32(client_tun_ip.into()).await?;
    address_stream.write_u32(ip_mask.into()).await?;

    info!(
        "Sent address information to client {} (remote address {})",
        client_tun_ip,
        connection.remote_address().ip()
    );

    let mut connection = QuincyConnection::new(connection, tun_worker.get_tun_sender());
    connection.start_worker()?;

    tun_worker
        .add_connection(IpAddr::V4(client_tun_ip), Arc::new(connection))
        .await;

    Ok(())
}

fn get_next_free_client_ip(server_ip: Ipv4Addr) -> Ipv4Addr {
    let mut server_ip_bytes = server_ip.octets();
    server_ip_bytes[3] = 2 as u8;

    Ipv4Addr::from(server_ip_bytes)
}
