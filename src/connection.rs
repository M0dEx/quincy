use crate::auth::{Auth, AuthClientMessage, AuthServerMessage, AuthState};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use delegate::delegate;
use ipnet::Ipv4Net;
use quinn::Connection;
use quinn::SendDatagramError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tun::Tun;
use tracing::debug;

type SharedAuthState = Arc<RwLock<AuthState>>;

pub struct QuincyConnection {
    connection: Arc<Connection>,
    client_address: Ipv4Net,
    auth: Arc<Auth>,
    auth_state: SharedAuthState,
    tun_queue: Arc<UnboundedSender<Bytes>>,
    authentication_worker: Option<JoinHandle<Result<()>>>,
    connection_worker: Option<JoinHandle<Result<()>>>,
}

impl QuincyConnection {
    pub fn new(
        connection: Connection,
        tun_queue: Arc<UnboundedSender<Bytes>>,
        auth: Arc<Auth>,
        client_address: Ipv4Net,
    ) -> Self {
        Self {
            connection: Arc::new(connection),
            client_address,
            auth,
            auth_state: Arc::new(RwLock::new(AuthState::Unauthenticated)),
            tun_queue,
            authentication_worker: None,
            connection_worker: None,
        }
    }

    async fn process_incoming_data(
        connection: Arc<Connection>,
        tun_queue: Arc<UnboundedSender<Bytes>>,
    ) -> Result<()> {
        loop {
            let data = connection.read_datagram().await?;
            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            tun_queue.send(data)?;
        }
    }

    async fn process_authentication_stream(
        connection: Arc<Connection>,
        auth: Arc<Auth>,
        auth_state: SharedAuthState,
        client_address: Ipv4Net,
    ) -> Result<()> {
        let (mut auth_stream_send, mut auth_stream_recv) = connection.open_bi().await?;
        // TODO: Make this configurable
        let auth_interval = Duration::from_secs(120);

        let mut buf = BytesMut::with_capacity(2048);

        loop {
            match timeout(auth_interval, auth_stream_recv.read_buf(&mut buf)).await {
                Ok(_) => {}
                Err(_) => *auth_state.write().await = AuthState::Failed,
            }

            let (message, _): (AuthClientMessage, usize) =
                bincode::decode_from_slice(&buf, bincode::config::standard())?;

            match (&*auth_state.read().await, message) {
                (AuthState::Authenticated(username), AuthClientMessage::SessionToken(token)) => {
                    if auth.verify_session_token(username, token.into())? {
                        let mut message_buf = BytesMut::with_capacity(4);
                        bincode::encode_into_slice(
                            AuthServerMessage::Ok,
                            &mut message_buf,
                            bincode::config::standard(),
                        )?;

                        auth_stream_send.write_all(&message_buf).await?
                    }
                }
                (
                    AuthState::Unauthenticated,
                    AuthClientMessage::Authentication(username, password),
                ) => {
                    let session_token = auth.authenticate(username, password).await?;
                    let mut message_buf = BytesMut::with_capacity(128);
                    bincode::encode_into_slice(
                        AuthServerMessage::Authenticated(
                            client_address.addr().into(),
                            client_address.netmask().into(),
                            session_token.into(),
                        ),
                        &mut message_buf,
                        bincode::config::standard(),
                    )?;

                    auth_stream_send.write_all(&message_buf).await?
                }
                _ => todo!("Close connection"),
            }
        }
    }

    pub fn start_worker(&mut self) -> Result<()> {
        if self.connection_worker.is_some() {
            return Err(anyhow!("There is already a worker active"));
        }

        self.authentication_worker = Some(tokio::spawn(Self::process_authentication_stream(
            self.connection.clone(),
            self.auth.clone(),
            self.auth_state.clone(),
            self.client_address,
        )));

        self.connection_worker = Some(tokio::spawn(Self::process_incoming_data(
            self.connection.clone(),
            self.tun_queue.clone(),
        )));

        Ok(())
    }

    delegate! {
        to self.connection {
            pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>;
            pub fn max_datagram_size(&self) -> Option<usize>;
            pub fn remote_address(&self) -> SocketAddr;
        }
    }
}

pub async fn relay_packets(connection: Arc<Connection>, interface: Tun, mtu: usize) -> Result<()> {
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
