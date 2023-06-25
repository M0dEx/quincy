use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::{sync::RwLock, time::timeout};

use crate::utils::{
    serde::ip_addr_to_bytes,
    streams::{AsyncReceiveBincode, AsyncSendBincode},
};

use super::{client::AuthClientMessage, user::UserDatabase, SessionToken};

/// Represents the internal authentication state for a session.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthState {
    Unauthenticated,
    Authenticated(String),
}

/// Represents an authentication message sent by the server.
#[derive(Encode, Decode)]
pub enum AuthServerMessage {
    Authenticated(Vec<u8>, Vec<u8>, SessionToken),
    Ok,
    Failed,
}

/// Represents an authentication server handling initial authentication and session management.
pub struct AuthServer {
    user_database: Arc<UserDatabase>,
    auth_timeout: Duration,
    auth_state: RwLock<AuthState>,
    client_address: IpNet,
    connection: Arc<Connection>,
    send_stream: RwLock<SendStream>,
    recv_stream: RwLock<RecvStream>,
}

impl AuthServer {
    pub async fn new(
        user_database: Arc<UserDatabase>,
        connection: Arc<Connection>,
        client_address: IpNet,
        auth_timeout: Duration,
    ) -> Result<Self> {
        let (send, recv) = connection.accept_bi().await?;

        Ok(Self {
            user_database,
            auth_timeout,
            auth_state: RwLock::new(AuthState::Unauthenticated),
            client_address,
            connection,
            send_stream: RwLock::new(send),
            recv_stream: RwLock::new(recv),
        })
    }

    /// Handles authentication for a client.
    pub async fn handle_authentication(&self) -> Result<()> {
        loop {
            let message: Option<AuthClientMessage> =
                timeout(self.auth_timeout, self.recv_message())
                    .await?
                    .ok()
                    .flatten();

            let state = self.get_state().await;

            match (state, message) {
                (
                    AuthState::Unauthenticated,
                    Some(AuthClientMessage::Authentication(username, password)),
                ) => self.authenticate_user(username, password).await?,
                (
                    AuthState::Authenticated(username),
                    Some(AuthClientMessage::SessionToken(token)),
                ) => self.verify_session_token(&username, token).await?,
                (_, None) => self.handle_timeout().await?,
                _ => self.handle_failure().await?,
            }
        }
    }

    pub async fn get_state(&self) -> AuthState {
        self.auth_state.read().await.clone()
    }

    /// Authenticates a user with the given username and password.
    async fn authenticate_user(&self, username: String, password: String) -> Result<()> {
        match self.user_database.authenticate(&username, password).await {
            Ok(session_token) => {
                let response = AuthServerMessage::Authenticated(
                    ip_addr_to_bytes(self.client_address.addr()),
                    ip_addr_to_bytes(self.client_address.netmask()),
                    session_token,
                );

                self.send_stream
                    .write()
                    .await
                    .send_message(response)
                    .await?;
                self.set_state(AuthState::Authenticated(username)).await;

                Ok(())
            }
            Err(_) => {
                self.close_connection("Invalid username or password")
                    .await?;

                Err(anyhow!("Invalid username or password"))
            }
        }
    }

    /// Verifies the sessions token sent by the user.
    async fn verify_session_token(
        &self,
        username: &str,
        session_token: SessionToken,
    ) -> Result<()> {
        if self
            .user_database
            .verify_session_token(username, session_token)?
        {
            self.send_message(AuthServerMessage::Ok).await?;

            Ok(())
        } else {
            self.send_message(AuthServerMessage::Failed).await?;
            self.close_connection("Invalid session token").await?;

            Err(anyhow!("Invalid session token"))
        }
    }

    /// Handles a timeout during authentication.
    async fn handle_timeout(&self) -> Result<()> {
        self.close_connection("Authentication timed out").await?;

        Err(anyhow!("Authentication timed out"))
    }

    /// Handles a failure during authentication.
    async fn handle_failure(&self) -> Result<()> {
        self.close_connection("Authentication failed").await?;

        Err(anyhow!("Authentication failed"))
    }

    /// Closes the connection with the given reason.
    async fn close_connection(&self, reason: &str) -> Result<()> {
        self.send_message(AuthServerMessage::Failed).await?;
        self.send_stream.write().await.finish().await?;

        self.connection
            .close(VarInt::from_u32(0x01), reason.as_bytes());

        self.set_state(AuthState::Unauthenticated).await;

        Ok(())
    }

    async fn send_message(&self, message: AuthServerMessage) -> Result<()> {
        self.send_stream.write().await.send_message(message).await?;

        Ok(())
    }

    async fn recv_message(&self) -> Result<Option<AuthClientMessage>> {
        self.recv_stream.write().await.receive_message().await
    }

    async fn set_state(&self, state: AuthState) {
        *self.auth_state.write().await = state;
    }
}
