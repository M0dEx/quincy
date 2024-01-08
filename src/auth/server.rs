use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::constants::{AUTH_FAILED_MESSAGE, AUTH_MESSAGE_BUFFER_SIZE, AUTH_TIMEOUT_MESSAGE};
use crate::server::address_pool::AddressPool;
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
pub struct AuthServer<'a> {
    user_database: &'a UserDatabase,
    address_pool: &'a AddressPool,
    connection: Arc<Connection>,
    auth_timeout: Duration,
}

impl<'a> AuthServer<'a> {
    pub fn new(
        user_database: &'a UserDatabase,
        address_pool: &'a AddressPool,
        connection: Arc<Connection>,
        auth_timeout: Duration,
    ) -> Self {
        Self {
            user_database,
            address_pool,
            connection,
            auth_timeout,
        }
    }

    /// Handles authentication for a client.
    pub async fn handle_authentication(&self) -> Result<(String, IpNet)> {
        let (send_stream, mut recv_stream) =
            match timeout(self.auth_timeout, self.connection.accept_bi()).await {
                Ok(Ok(streams)) => streams,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    return Err(self
                        .handle_failure(AUTH_TIMEOUT_MESSAGE, None)
                        .await
                        .expect_err("Handle failure always returns an error"))
                }
            };

        match timeout(self.auth_timeout, Self::recv_message(&mut recv_stream)).await {
            Ok(Ok(AuthClientMessage::Authentication(username, password))) => {
                self.authenticate_user(send_stream, username, password)
                    .await
            }
            Ok(Err(_)) => Err(self
                .handle_failure(AUTH_FAILED_MESSAGE, Some(send_stream))
                .await
                .expect_err("Handle failure always returns an error")),
            Err(_) => Err(self
                .handle_failure(AUTH_TIMEOUT_MESSAGE, Some(send_stream))
                .await
                .expect_err("Handle failure always returns an error")),
        }
    }

    /// Authenticates a user with the given username and password.
    async fn authenticate_user(
        &self,
        mut send_stream: SendStream,
        username: String,
        password: String,
    ) -> Result<(String, IpNet)> {
        let auth_result = self.user_database.authenticate(&username, password).await;

        if auth_result.is_err() {
            return Err(self
                .handle_failure(AUTH_FAILED_MESSAGE, Some(send_stream))
                .await
                .expect_err("Handle failure always returns an error"));
        }

        let client_address = self
            .address_pool
            .next_available_address()
            .ok_or_else(|| anyhow!("Could not find an available address for client"))?;

        let response =
            AuthServerMessage::Authenticated(client_address.addr(), client_address.netmask());

        Self::send_message(&mut send_stream, response).await?;

        Ok((username, client_address))
    }

    /// Handles a failure during authentication.
    async fn handle_failure(
        &self,
        reason: &'static str,
        send_stream: Option<SendStream>,
    ) -> Result<()> {
        if let Some(mut send_stream) = send_stream {
            Self::send_message(&mut send_stream, AuthServerMessage::Failed).await?;
            send_stream.finish().await?;
        }

        self.close_connection(reason).await?;

        Err(anyhow!(reason))
    }

    /// Closes the connection with the given reason.
    async fn close_connection(&self, reason: &str) -> Result<()> {
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
