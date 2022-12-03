use std::sync::Arc;
use crate::Args;

use anyhow::{anyhow, Result};
use quinn::{Connection, TransportConfig};
use tokio_tun::{Tun, TunBuilder};
use tracing::info;
use crate::connection::relay_packets;
use crate::utils::{bind_socket, PERF_CIPHER_SUITES};

pub async fn run_server(args: Args) -> Result<()> {

    let self_signed =  rcgen::generate_simple_self_signed(vec!["localhost".into()])?;

    let key = rustls::PrivateKey(self_signed.serialize_private_key_der());
    let cert = vec![rustls::Certificate(self_signed.serialize_der()?)];

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    crypto.alpn_protocols = vec![b"quincy".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(None);
    transport.initial_max_udp_payload_size(1400);

    server_config.transport_config(Arc::new(transport));

    let socket = bind_socket(args.host, 2097152, 2097152)?;

    let endpoint = quinn::Endpoint::new(
        Default::default(),
        Some(server_config),
        socket,
        quinn::TokioRuntime
    )?;

    info!("Listening on {}", endpoint.local_addr().unwrap());

    let tun_ip = "10.0.0.1".parse()?;
    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .mtu(1350)
        .up()
        .address(tun_ip)
        .destination("10.0.1.1".parse()?)
        .netmask("255.255.255.255".parse()?)
        .try_build()
        .map_err(|e| anyhow!("{e}"))?;

    info!("Created a tun interface with IP: {tun_ip}");

    handle(endpoint.accept().await.ok_or(anyhow!("No connection"))?, tun).await?;

    Ok(())
}

async fn handle(handshake: quinn::Connecting, interface: Tun) -> Result<()> {
    let connection: Connection = handshake.await?;
    info!("{:?} connected", connection.remote_address());

    relay_packets(Arc::new(connection), interface).await?;

    Ok(())
}
