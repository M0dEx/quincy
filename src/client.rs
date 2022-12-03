use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use anyhow::{anyhow, Result};
use quinn::TransportConfig;
use tokio_tun::TunBuilder;
use tracing::info;
use crate::Args;
use crate::connection::relay_packets;
use crate::utils::{bind_socket, PERF_CIPHER_SUITES};

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

pub async fn run_client(args: Args) -> Result<()> {

    let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);

    info!("Local address: {:?}", bind_addr);
    info!("Connecting to: {:?}", args.host);

    let socket = bind_socket(bind_addr, 2097152, 2097152)?;

    let endpoint = quinn::Endpoint::new(Default::default(), None, socket, quinn::TokioRuntime)?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"quincy".to_vec()];

    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(None);
    transport.initial_max_udp_payload_size(1400);

    cfg.transport_config(Arc::new(transport));

    let connection = endpoint
    .connect_with(cfg, args.host, "localhost")?
    .await?;

    info!("Connection established: {:?}", args.host);

    let tun_ip = "10.0.1.1".parse()?;
    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .mtu(1350)
        .up()
        .address(tun_ip)
        .destination("10.0.0.1".parse()?)
        .netmask("255.255.255.255".parse()?)
        .try_build()
        .map_err(|e| anyhow!("{e}"))?;

    info!("Created a tun interface with IP: {tun_ip}");

    relay_packets(Arc::new(connection), tun).await?;

    Ok(())
}
