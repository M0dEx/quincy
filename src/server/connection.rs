use crate::auth::{Auth, AuthClientMessage, AuthServerMessage, AuthState};
use crate::utils::encode_message;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use delegate::delegate;
use ipnet::Ipv4Net;
use quinn::Connection;
use quinn::SendDatagramError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::timeout;
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
                        let data = encode_message(AuthServerMessage::Ok)?;
                        auth_stream_send.write_all(&data).await?
                    }
                }
                (
                    AuthState::Unauthenticated,
                    AuthClientMessage::Authentication(username, password),
                ) => {
                    let session_token = auth.authenticate(&username, password).await?;
                    let response = AuthServerMessage::Authenticated(
                        client_address.addr().into(),
                        client_address.netmask().into(),
                        session_token.into(),
                    );

                    let data = encode_message(response)?;
                    auth_stream_send.write_all(&data).await?
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
