use crate::auth::{Auth, AuthClientMessage, AuthServerMessage, AuthState};
use crate::constants::{AUTH_TIMEOUT_GRACE, BINCODE_BUFFER_SIZE};
use crate::utils::serde::{decode_message, encode_message, ip_addr_to_bytes};
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use delegate::delegate;
use ipnet::IpNet;
use quinn::SendDatagramError;
use quinn::{Connection, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error};

type SharedAuthState = Arc<RwLock<AuthState>>;

/// Represents a Quincy connection encapsulating authentication and IO.
pub struct QuincyConnection {
    connection: Arc<Connection>,
    client_address: IpNet,
    auth: Arc<Auth>,
    auth_state: SharedAuthState,
    auth_timeout: u32,
    tun_queue: Arc<UnboundedSender<Bytes>>,
    authentication_worker: Option<JoinHandle<Result<()>>>,
    connection_worker: Option<JoinHandle<Result<()>>>,
}

impl QuincyConnection {
    /// Creates a new instance of the Quincy connection.
    ///
    /// ### Arguments
    /// - `connection` - the underlying QUIC connection
    /// - `tun_queue` - a sender of an unbounded queue used by the tunnel worker to receive data
    /// - `auth` - a reference to the authentication module
    /// - `client_address` - an address and network mask to be used by the client after successful authentication
    pub fn new(
        connection: Connection,
        tun_queue: Arc<UnboundedSender<Bytes>>,
        auth: Arc<Auth>,
        auth_timeout: u32,
        client_address: IpNet,
    ) -> Self {
        Self {
            connection: Arc::new(connection),
            client_address,
            auth,
            auth_state: Arc::new(RwLock::new(AuthState::Unauthenticated)),
            auth_timeout,
            tun_queue,
            authentication_worker: None,
            connection_worker: None,
        }
    }

    /// Checks whether the workers for this connection are still running.
    ///
    /// ### Returns
    /// - `true` if the authentication and connection workers are running, `false` if not
    pub fn is_ok(&self) -> bool {
        let authentication_worker_ok = self
            .authentication_worker
            .as_ref()
            .map(|worker| !worker.is_finished())
            .unwrap_or(false);

        let connection_worker_ok = self
            .connection_worker
            .as_ref()
            .map(|worker| !worker.is_finished())
            .unwrap_or(false);

        authentication_worker_ok && connection_worker_ok
    }

    /// Start the authentication and connection workers for this connection.
    pub fn start_worker(&mut self) -> Result<()> {
        if self.authentication_worker.is_some() || self.connection_worker.is_some() {
            return Err(anyhow!("Workers have been already started"));
        }

        self.authentication_worker = Some(tokio::spawn(Self::process_authentication_stream(
            self.connection.clone(),
            self.auth.clone(),
            self.auth_state.clone(),
            self.auth_timeout,
            self.client_address,
        )));

        self.connection_worker = Some(tokio::spawn(Self::process_incoming_data(
            self.connection.clone(),
            self.tun_queue.clone(),
        )));

        Ok(())
    }

    /// Stops the authentication and connection workers for this connection.
    pub async fn stop_workers(&mut self) -> Result<()> {
        self.authentication_worker
            .take()
            .ok_or_else(|| anyhow!("Authentication worker does not exist"))?
            .abort();
        self.connection_worker
            .take()
            .ok_or_else(|| anyhow!("Connection worker does not exist"))?
            .abort();

        Ok(())
    }

    delegate! {
        to self.connection {
            pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>;
            pub fn max_datagram_size(&self) -> Option<usize>;
            pub fn remote_address(&self) -> SocketAddr;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    ///
    /// ### Arguments
    /// - `connection` - a reference to the underlying QUIC connection
    /// - `tun_queue` - a sender of an unbounded queue used by the tunnel worker to receive data
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

    /// Processes incoming and outgoing authentication messages.
    ///
    /// ### Arguments
    /// - `connection` - a reference to the underlying QUIC connection
    /// - `auth` - a reference to the authentication module
    /// - `auth_state` - a reference to the authentication state for this connection
    /// - `client_address` - an address and network mask intended to be used by the client after successful authentication
    async fn process_authentication_stream(
        connection: Arc<Connection>,
        auth: Arc<Auth>,
        auth_state: SharedAuthState,
        auth_timeout: u32,
        client_address: IpNet,
    ) -> Result<()> {
        let (mut auth_stream_send, mut auth_stream_recv) = connection.accept_bi().await?;
        let auth_interval = Duration::from_secs(auth_timeout as u64 + AUTH_TIMEOUT_GRACE);

        loop {
            let mut buf = BytesMut::with_capacity(BINCODE_BUFFER_SIZE);

            let message: Option<AuthClientMessage> =
                match timeout(auth_interval, auth_stream_recv.read_buf(&mut buf)).await {
                    Ok(_) => Some(decode_message(buf.into())?),
                    Err(_) => None,
                };

            let state = auth_state.read().await.clone();
            let mut new_state: AuthState = state.clone();

            match (state, message) {
                (
                    AuthState::Authenticated(username),
                    Some(AuthClientMessage::SessionToken(token)),
                ) => {
                    if auth.verify_session_token(&username, token)? {
                        let data = encode_message(AuthServerMessage::Ok)?;
                        auth_stream_send.write_all(&data).await?
                    }
                }
                (
                    AuthState::Unauthenticated,
                    Some(AuthClientMessage::Authentication(username, password)),
                ) => {
                    let session_token = auth.authenticate(&username, password).await?;
                    let response = AuthServerMessage::Authenticated(
                        ip_addr_to_bytes(client_address.addr()),
                        ip_addr_to_bytes(client_address.netmask()),
                        session_token,
                    );

                    let data = encode_message(response)?;
                    auth_stream_send.write_all(&data).await?;
                    new_state = AuthState::Authenticated(username);
                }
                (_, None) => {
                    error!("Client {} timed out", client_address.addr());
                    // TODO: Use consts for QUIC error codes
                    let data = encode_message(AuthServerMessage::Failed)?;
                    auth_stream_send.write_all(&data).await?;
                    auth_stream_send.finish().await?;
                    connection.close(
                        VarInt::from_u32(0x01),
                        "Authentication timed out".as_bytes(),
                    );
                    break;
                }
                _ => {
                    error!("Client {} authentication failed", client_address.addr());
                    let data = encode_message(AuthServerMessage::Failed)?;
                    auth_stream_send.write_all(&data).await?;
                    auth_stream_send.finish().await?;
                    connection.close(VarInt::from_u32(0x01), "Invalid authentication".as_bytes());
                    break;
                }
            }

            *auth_state.write().await = new_state;
        }

        Ok(())
    }
}
