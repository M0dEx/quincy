use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::constants::{AUTH_FAILED_MESSAGE, AUTH_MESSAGE_BUFFER_SIZE};
use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, time::timeout};

use super::{client::AuthClientMessage, user::UserDatabase};

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
    username: Option<String>,
    client_address: IpNet,
    connection: Arc<Connection>,
    auth_timeout: Duration,
}

impl AuthServer {
    pub fn new(
        user_database: Arc<UserDatabase>,
        connection: Arc<Connection>,
        client_address: IpNet,
        auth_timeout: Duration,
    ) -> Self {
        Self {
            user_database,
            username: None,
            client_address,
            connection,
            auth_timeout,
        }
    }

    /// Handles authentication for a client.
    pub async fn handle_authentication(&mut self) -> Result<()> {
        let (send_stream, mut recv_stream) = self.connection.accept_bi().await?;

        let message = timeout(self.auth_timeout, Self::recv_message(&mut recv_stream)).await?;

        if let Ok(AuthClientMessage::Authentication(username, password)) = message {
            self.authenticate_user(send_stream, username, password)
                .await
        } else {
            self.handle_failure(send_stream).await
        }
    }

    /// Authenticates a user with the given username and password.
    async fn authenticate_user(
        &mut self,
        mut send_stream: SendStream,
        username: String,
        password: String,
    ) -> Result<()> {
        let auth_result = self.user_database.authenticate(&username, password).await;

        if auth_result.is_err() {
            return self.handle_failure(send_stream).await;
        }

        let response = AuthServerMessage::Authenticated(
            self.client_address.addr(),
            self.client_address.netmask(),
        );

        Self::send_message(&mut send_stream, response).await?;
        self.username.replace(username);

        Ok(())
    }

    /// Handles a failure during authentication.
    async fn handle_failure(&self, send_stream: SendStream) -> Result<()> {
        self.close_connection(send_stream, AUTH_FAILED_MESSAGE)
            .await?;

        Err(anyhow!(AUTH_FAILED_MESSAGE))
    }

    /// Closes the connection with the given reason.
    async fn close_connection(&self, mut send_stream: SendStream, reason: &str) -> Result<()> {
        Self::send_message(&mut send_stream, AuthServerMessage::Failed).await?;
        send_stream.finish().await?;

        self.connection
            .close(VarInt::from_u32(0x01), reason.as_bytes());

        Ok(())
    }

    #[inline]
    async fn send_message(send_stream: &mut SendStream, message: AuthServerMessage) -> Result<()> {
        send_stream
            .write_all(&serde_json::to_vec(&message)?)
            .await
            .context("Failed to send AuthServerMessage")
    }

    #[inline]
    async fn recv_message(recv_stream: &mut RecvStream) -> Result<AuthClientMessage> {
        let mut buf = BytesMut::with_capacity(AUTH_MESSAGE_BUFFER_SIZE);
        recv_stream.read_buf(&mut buf).await?;

        serde_json::from_slice(&buf).context("Failed to parse AuthClientMessage")
    }
}
