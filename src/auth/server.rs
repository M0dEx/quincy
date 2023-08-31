use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, sync::RwLock, time::timeout};

use super::{client::AuthClientMessage, user::UserDatabase};

/// Represents the internal authentication state for a session.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthState {
    Unauthenticated,
    Authenticated(String),
}

/// Represents an authentication message sent by the server.
#[derive(Serialize, Deserialize)]
pub enum AuthServerMessage {
    Authenticated(IpAddr, IpAddr),
    Ok,
    Failed,
}

/// Represents an authentication server handling initial authentication and session management.
pub struct AuthServer {
    user_database: Arc<UserDatabase>,
    auth_state: RwLock<AuthState>,
    client_address: IpNet,
    connection: Arc<Connection>,
    send_stream: SendStream,
    recv_stream: RecvStream,
    auth_timeout: Duration,
}

impl AuthServer {
    pub async fn new(
        user_database: Arc<UserDatabase>,
        connection: Arc<Connection>,
        client_address: IpNet,
        auth_timeout: Duration,
    ) -> Result<Self> {
        let (send_stream, recv_stream) = connection.accept_bi().await?;

        Ok(Self {
            user_database,
            auth_state: RwLock::new(AuthState::Unauthenticated),
            client_address,
            connection,
            send_stream,
            recv_stream,
            auth_timeout,
        })
    }

    /// Handles authentication for a client.
    pub async fn handle_authentication(&mut self) -> Result<()> {
        let message: Option<AuthClientMessage> = timeout(self.auth_timeout, self.recv_message())
            .await?
            .ok()
            .flatten();

        let state = self.get_state().await;

        match (state, message) {
            (
                AuthState::Unauthenticated,
                Some(AuthClientMessage::Authentication(username, password)),
            ) => self.authenticate_user(username, password).await,
            _ => self.handle_failure().await,
        }
    }

    /// Authenticates a user with the given username and password.
    async fn authenticate_user(&mut self, username: String, password: String) -> Result<()> {
        if self
            .user_database
            .authenticate(&username, password)
            .await
            .is_err()
        {
            self.close_connection("Invalid username or password")
                .await?;

            return Err(anyhow!("Invalid username or password"));
        }

        let response = AuthServerMessage::Authenticated(
            self.client_address.addr(),
            self.client_address.netmask(),
        );

        self.send_message(response).await?;
        self.set_state(AuthState::Authenticated(username)).await;

        Ok(())
    }

    /// Handles a failure during authentication.
    async fn handle_failure(&mut self) -> Result<()> {
        self.close_connection("Authentication failed").await?;

        Err(anyhow!("Authentication failed"))
    }

    /// Closes the connection with the given reason.
    async fn close_connection(&mut self, reason: &str) -> Result<()> {
        self.send_message(AuthServerMessage::Failed).await?;
        self.send_stream.finish().await?;

        self.connection
            .close(VarInt::from_u32(0x01), reason.as_bytes());

        self.set_state(AuthState::Unauthenticated).await;

        Ok(())
    }

    #[inline]
    async fn send_message(&mut self, message: AuthServerMessage) -> Result<()> {
        self.send_stream
            .write_all(&serde_json::to_vec(&message)?)
            .await
            .context("Failed to send AuthServerMessage")
    }

    #[inline]
    async fn recv_message(&mut self) -> Result<Option<AuthClientMessage>> {
        let mut buf = BytesMut::with_capacity(1024);
        self.recv_stream.read_buf(&mut buf).await?;

        serde_json::from_slice(&buf).context("Failed to parse AuthClientMessage")
    }

    pub async fn get_state(&self) -> AuthState {
        self.auth_state.read().await.clone()
    }

    async fn set_state(&self, state: AuthState) {
        *self.auth_state.write().await = state;
    }
}
