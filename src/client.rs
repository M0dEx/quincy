use crate::auth::{AuthClientMessage, AuthServerMessage, SessionToken};

use crate::config::ClientConfig;
use crate::constants::BINCODE_BUFFER_SIZE;
use crate::utils::{bind_socket, decode_message, encode_message};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use ipnet::Ipv4Net;
use quinn::{Connection, Endpoint, RecvStream, SendStream};

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::sleep;
use tokio::try_join;
use tokio_tun::{Tun, TunBuilder};
use tracing::{debug, info};

pub struct QuincyClient {
    client_config: ClientConfig,
}

impl QuincyClient {
    pub fn new(client_config: ClientConfig) -> Self {
        Self { client_config }
    }

    pub async fn run(&self) -> Result<()> {
        let connection = self.connect_to_server().await?;

        let (mut auth_send, mut auth_receive) = connection.open_bi().await?;
        let (assigned_address, session_token) =
            self.authenticate(&mut auth_send, &mut auth_receive).await?;

        debug!("Received TUN address: {assigned_address}");

        let tun = TunBuilder::new()
            .name("")
            .tap(false)
            .packet_info(false)
            .mtu(self.client_config.connection.mtu as i32)
            .up()
            .address(assigned_address.addr())
            .netmask(assigned_address.netmask())
            .try_build()
            .map_err(|e| anyhow!("Failed to create a TUN interface: {e}"))?;

        try_join!(
            self.manage_session(auth_send, auth_receive, session_token),
            self.relay_packets(connection, tun),
        )?;

        Ok(())
    }

    async fn connect_to_server(&self) -> Result<Connection> {
        let quinn_config = self.client_config.as_quinn_client_config()?;
        let endpoint = self.create_quinn_endpoint()?;

        let server_hostname = self
            .client_config
            .connection_string
            .split(':')
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Could not parse hostname from connection string '{}'",
                    self.client_config.connection_string
                )
            })?;

        let server_addr = self
            .client_config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Connection string '{}' is invalid",
                    self.client_config.connection_string
                )
            })?;

        info!("Connecting to '{}'", self.client_config.connection_string);
        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;
        info!(
            "Connection to '{}' established",
            self.client_config.connection_string
        );

        Ok(connection)
    }

    fn create_quinn_endpoint(&self) -> Result<Endpoint> {
        let bind_addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        info!("Local address: {:?}", bind_addr);

        let socket = bind_socket(
            bind_addr,
            self.client_config.connection.send_buffer_size as usize,
            self.client_config.connection.recv_buffer_size as usize,
        )?;

        let endpoint = Endpoint::new(Default::default(), None, socket, quinn::TokioRuntime)?;

        Ok(endpoint)
    }

    async fn authenticate(
        &self,
        auth_send: &mut SendStream,
        auth_recv: &mut RecvStream,
    ) -> Result<(Ipv4Net, SessionToken)> {
        let basic_auth = AuthClientMessage::Authentication(
            self.client_config.authentication.username.clone(),
            self.client_config.authentication.password.clone(),
        );

        let buf = encode_message(basic_auth)?;
        auth_send.write_all(&buf).await?;

        let mut buf = BytesMut::with_capacity(BINCODE_BUFFER_SIZE);
        auth_recv.read_buf(&mut buf).await?;

        // FIXME: This should not be necessary
        let auth_response = if !buf.is_empty() {
            decode_message(buf.into())?
        } else {
            AuthServerMessage::Failed
        };

        match auth_response {
            AuthServerMessage::Authenticated(addr_data, netmask_data, session_token) => Ok((
                Ipv4Net::with_netmask(addr_data.into(), netmask_data.into())?,
                session_token,
            )),
            _ => Err(anyhow!("Authentication failed")),
        }
    }

    async fn manage_session(
        &self,
        mut auth_send: SendStream,
        mut auth_recv: RecvStream,
        session_token: SessionToken,
    ) -> Result<()> {
        let auth_interval =
            Duration::from_secs(self.client_config.authentication.auth_timeout as u64);

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

    async fn relay_packets(&self, connection: Connection, interface: Tun) -> Result<()> {
        let connection = Arc::new(connection);
        let (read, write) = tokio::io::split(interface);

        try_join!(
            Self::handle_send(
                connection.clone(),
                read,
                self.client_config.connection.mtu as usize
            ),
            Self::handle_recv(connection.clone(), write)
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
                anyhow!(
                    "The other side of the connection is refusing to provide a max datagram size"
                )
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
}
