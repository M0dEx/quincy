use crate::auth::{AuthClientMessage, AuthServerMessage, SessionToken};
use crate::certificates::load_certificates_from_file;
use crate::config::{ClientConfig, ConnectionConfig};
use crate::constants::{
    BINCODE_BUFFER_SIZE, QUIC_MTU_OVERHEAD, QUINCY_CIPHER_SUITES, TLS_ALPN_PROTOCOLS,
    TLS_PROTOCOL_VERSIONS,
};
use crate::utils::{bind_socket, decode_message, encode_message};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use ipnet::Ipv4Net;
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::{Certificate, RootCertStore};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::sleep;
use tokio_tun::{Tun, TunBuilder};
use tracing::{debug, error, info};

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
    info!("Connecting to: {:?}", config.connection_address);

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

    info!("Connection established: {:?}", config.connection_address);

    let (mut auth_send, mut auth_receive) = connection.open_bi().await?;
    let (address, session_token) = authenticate(&config, &mut auth_send, &mut auth_receive).await?;

    let session_task = tokio::spawn(manage_session(auth_send, auth_receive, session_token));

    debug!("Received TUN IP address {address}");

    let tun = TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .mtu(config.connection.mtu as i32)
        .up()
        .address(address.addr())
        .netmask(address.netmask())
        .try_build()
        .map_err(|e| anyhow!("Failed to create a TUN interface: {e}"))?;

    debug!("Created a TUN interface");

    relay_packets(Arc::new(connection), tun, config.connection.mtu as usize).await?;
    session_task.await??;

    Ok(())
}

async fn authenticate(
    client_config: &ClientConfig,
    auth_send: &mut SendStream,
    auth_recv: &mut RecvStream,
) -> Result<(Ipv4Net, SessionToken)> {
    let basic_auth = AuthClientMessage::Authentication(
        client_config.authentication.username.clone(),
        client_config.authentication.password.clone(),
    );

    let buf = encode_message(basic_auth)?;
    auth_send.write_all(&buf).await?;

    let mut buf = BytesMut::with_capacity(BINCODE_BUFFER_SIZE);
    auth_recv.read_buf(&mut buf).await?;

    let auth_response: AuthServerMessage = decode_message(buf.into())?;

    match auth_response {
        AuthServerMessage::Authenticated(addr_data, netmask_data, session_token) => Ok((
            Ipv4Net::with_netmask(addr_data.into(), netmask_data.into())?,
            session_token,
        )),
        _ => Err(anyhow!("Authentication failed")),
    }
}

async fn manage_session(
    mut auth_send: SendStream,
    mut auth_recv: RecvStream,
    session_token: SessionToken,
) -> Result<()> {
    let auth_interval = Duration::from_secs(100);

    let message = AuthClientMessage::SessionToken(session_token);
    let buf = encode_message(message)?;

    loop {
        auth_send.write_all(&buf).await?;

        let mut response_buf = BytesMut::with_capacity(BINCODE_BUFFER_SIZE);
        auth_recv.read_buf(&mut response_buf).await?;

        let auth_response: AuthServerMessage = decode_message(response_buf.into())?;

        match auth_response {
            AuthServerMessage::Ok => {}
            _ => return Err(anyhow!("Session died")),
        }

        sleep(auth_interval).await;
    }
}

async fn relay_packets(connection: Arc<Connection>, interface: Tun, mtu: usize) -> Result<()> {
    let (read, write) = tokio::io::split(interface);

    let (_, _) = tokio::try_join!(
        tokio::spawn(handle_send(connection.clone(), read, mtu)),
        tokio::spawn(handle_recv(connection.clone(), write))
    )?;

    Ok(())
}

async fn handle_send(
    connection: Arc<Connection>,
    mut read_interface: ReadHalf<Tun>,
    interface_mtu: usize,
) -> Result<()> {
    debug!("Started send task");
    loop {
        let buf_size = connection.max_datagram_size().ok_or_else(|| {
            anyhow!("The other side of the connection is refusing to provide a max datagram size")
        })?;

        if interface_mtu > buf_size {
            return Err(anyhow!(
                "Interface MTU ({interface_mtu}) is higher than QUIC connection MTU ({buf_size})"
            ));
        }

        let mut buf = BytesMut::with_capacity(buf_size);
        read_interface.read_buf(&mut buf).await?;
        debug!(
            "Sending {} bytes to {:?}",
            buf.len(),
            connection.remote_address()
        );

        connection.send_datagram(buf.into())?;
    }
}

async fn handle_recv(
    connection: Arc<Connection>,
    mut write_interface: WriteHalf<Tun>,
) -> Result<()> {
    debug!("Started recv task");
    loop {
        let data = connection.read_datagram().await?;
        debug!(
            "Received {} bytes from {:?}",
            data.len(),
            connection.remote_address()
        );

        write_interface.write_all(&data).await?;
    }
}
