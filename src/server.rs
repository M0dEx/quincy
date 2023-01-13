use std::sync::Arc;
use crate::Args;
use crate::tun::make_tun;

use anyhow::{anyhow, Result};
use quinn::{Connection, TransportConfig};
use tokio_tun::Tun;
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
