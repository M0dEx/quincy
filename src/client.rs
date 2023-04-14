use crate::auth::{AuthClientMessage, AuthServerMessage, SessionToken};

use crate::config::ClientConfig;
use crate::constants::BINCODE_BUFFER_SIZE;
use crate::utils::{
    serde::{decode_message, encode_message, ip_addr_from_bytes},
    socket::bind_socket,
};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, Endpoint, RecvStream, SendStream};

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

use crate::utils::interface::{read_from_interface, set_up_interface, write_to_interface};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::time::sleep;
use tokio::try_join;
use tracing::{debug, info};
use tun::AsyncDevice;

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient {
    client_config: ClientConfig,
}

impl QuincyClient {
    /// Creates a new instance of a Quincy client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(client_config: ClientConfig) -> Self {
        Self { client_config }
    }

    /// Connects to the Quincy server and starts the workers for this instance of the Quincy client.
    pub async fn run(&self) -> Result<()> {
        let connection = self.connect_to_server().await?;

        let (mut auth_send, mut auth_receive) = connection.open_bi().await?;
        let (assigned_address, session_token) =
            self.authenticate(&mut auth_send, &mut auth_receive).await?;

        debug!("Received TUN address: {assigned_address}");

        let interface = set_up_interface(assigned_address, self.client_config.connection.mtu)?;

        try_join!(
            self.manage_session(auth_send, auth_receive, session_token),
            self.relay_packets(connection, interface),
        )?;

        Ok(())
    }

    /// Connects to the Quincy server.
    ///
    /// ### Returns
    /// - `Connection` - a Quinn connection representing the connection to the Quincy server
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

    /// Creates a Quinn endpoint.
    ///
    /// ### Returns
    /// - `Endpoint` - the Quinn endpoint
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

    /// Authenticates with the Quincy server.
    ///
    /// ### Arguments
    /// - `auth_send` - the send stream for the authentication channel
    /// - `auth_recv` - the receive stream for the authentication channel
    ///
    /// ### Returns
    /// - `IpNet, SessionToken` - the assigned TUN address and the session token
    async fn authenticate(
        &self,
        auth_send: &mut SendStream,
        auth_recv: &mut RecvStream,
    ) -> Result<(IpNet, SessionToken)> {
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
            AuthServerMessage::Authenticated(addr_data, netmask_data, session_token) => {
                let address = IpNet::with_netmask(
                    ip_addr_from_bytes(&addr_data)?,
                    ip_addr_from_bytes(&netmask_data)?,
                )?;

                Ok((address, session_token))
            }
            _ => Err(anyhow!("Authentication failed")),
        }
    }

    /// Manages the session with the Quincy server.
    ///
    /// ### Arguments
    /// - `auth_send` - the send stream for the authentication channel
    /// - `auth_recv` - the receive stream for the authentication channel
    /// - `session_token` - the session token
    async fn manage_session(
        &self,
        mut auth_send: SendStream,
        mut auth_recv: RecvStream,
        session_token: SessionToken,
    ) -> Result<()> {
        let auth_interval =
            Duration::from_secs(self.client_config.authentication.auth_interval as u64);

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

    /// Relays packets between the TUN interface and the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - the TUN interface
    async fn relay_packets(&self, connection: Connection, interface: AsyncDevice) -> Result<()> {
        let connection = Arc::new(connection);
        let (read, write) = tokio::io::split(interface);

        let (outbound_task, inbound_task) = try_join!(
            tokio::spawn(Self::process_outbound_traffic(
                connection.clone(),
                read,
                self.client_config.connection.mtu as usize
            )),
            tokio::spawn(Self::process_inbound_traffic(connection.clone(), write))
        )?;

        inbound_task?;
        outbound_task?;

        Ok(())
    }

    /// Handles incoming packets from the TUN interface and relays them to the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `read_interface` - the read half of the TUN interface
    /// - `interface_mtu` - the MTU of the TUN interface
    async fn process_outbound_traffic(
        connection: Arc<Connection>,
        mut read_interface: ReadHalf<AsyncDevice>,
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

            let data = read_from_interface(&mut read_interface, buf_size).await?;

            debug!(
                "Sending {} bytes to {:?}",
                data.len(),
                connection.remote_address()
            );

            connection.send_datagram(data)?;
        }
    }

    /// Handles incoming packets from the Quincy server and relays them to the TUN interface.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `write_interface` - the write half of the TUN interface
    async fn process_inbound_traffic(
        connection: Arc<Connection>,
        mut write_interface: WriteHalf<AsyncDevice>,
    ) -> Result<()> {
        debug!("Started recv task");
        loop {
            let data = connection.read_datagram().await?;
            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            write_to_interface(&mut write_interface, data).await?;
        }
    }
}
