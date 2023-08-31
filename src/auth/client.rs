use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::config::ClientAuthenticationConfig;

use super::server::AuthServerMessage;

/// Represents an authentication message sent by the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthClientMessage {
    Authentication(String, String),
}

/// Represents an authentication client handling initial authentication and session management.
pub struct AuthClient {
    send_stream: SendStream,
    recv_stream: RecvStream,
    username: String,
    password: String,
}

impl AuthClient {
    pub async fn new(
        connection: &Connection,
        authentication_config: &ClientAuthenticationConfig,
    ) -> Result<Self> {
        let (send, recv) = connection.open_bi().await?;

        Ok(Self {
            send_stream: send,
            recv_stream: recv,
            username: authentication_config.username.clone(),
            password: authentication_config.password.clone(),
        })
    }

    /// Establishes a session with the server.
    ///
    /// ### Returns
    /// - `IpNet` - the tunnel address received from the server
    pub async fn authenticate(&mut self) -> Result<IpNet> {
        let basic_auth =
            AuthClientMessage::Authentication(self.username.clone(), self.password.clone());

        self.send_message(basic_auth).await?;
        let auth_response = self.recv_message().await?;

        match auth_response {
            Some(AuthServerMessage::Authenticated(addr, netmask)) => {
                let address = IpNet::with_netmask(addr, netmask)?;

                Ok(address)
            }
            _ => Err(anyhow!("Authentication failed")),
        }
    }

    #[inline]
    async fn send_message(&mut self, message: AuthClientMessage) -> Result<()> {
        self.send_stream
            .write_all(&serde_json::to_vec(&message)?)
            .await
            .context("Failed to send AuthServerMessage")
    }

    #[inline]
    async fn recv_message(&mut self) -> Result<Option<AuthServerMessage>> {
        let mut buf = BytesMut::with_capacity(1024);
        self.recv_stream.read_buf(&mut buf).await?;

        serde_json::from_slice(&buf).context("Failed to parse AuthClientMessage")
    }
}
