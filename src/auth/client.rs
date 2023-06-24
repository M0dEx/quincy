use std::time::Duration;

use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream};
use tokio::time::sleep;

use crate::{
    config::ClientAuthenticationConfig,
    utils::{
        serde::ip_addr_from_bytes,
        streams::{AsyncReceiveBincode, AsyncSendBincode},
    },
};

use super::{AuthServerMessage, SessionToken};

/// Represents an authentication message sent by the client.
#[derive(Encode, Decode, Clone, Debug)]
pub enum AuthClientMessage {
    Authentication(String, String),
    SessionToken(SessionToken),
}

/// Represents an authentication client handling initial authentication and session management.
pub struct AuthClient {
    send_stream: SendStream,
    recv_stream: RecvStream,
    username: String,
    password: String,
    auth_interval: Duration,
    session_token: Option<SessionToken>,
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
            auth_interval: Duration::from_secs(authentication_config.auth_interval as u64),
            session_token: None,
        })
    }

    /// Establishes a session with the server.
    ///
    /// ### Returns
    /// - `IpNet` - the tunnel address received from the server
    pub async fn authenticate(&mut self) -> Result<IpNet> {
        let basic_auth =
            AuthClientMessage::Authentication(self.username.clone(), self.password.clone());

        self.send_stream.send_message(basic_auth).await?;
        let auth_response: AuthServerMessage = self.recv_stream.receive_message().await?;

        match auth_response {
            AuthServerMessage::Authenticated(addr_data, netmask_data, session_token) => {
                let address = IpNet::with_netmask(
                    ip_addr_from_bytes(&addr_data)?,
                    ip_addr_from_bytes(&netmask_data)?,
                )?;

                self.session_token = Some(session_token);

                Ok(address)
            }
            _ => Err(anyhow!("Authentication failed")),
        }
    }

    /// Sends the session token with the configured interval to maintain the established session.
    pub async fn maintain_session(&mut self) -> Result<()> {
        let session_token_msg = self
            .session_token
            .map(AuthClientMessage::SessionToken)
            .ok_or_else(|| anyhow!("Cannot maintain session without a session token"))?;

        loop {
            self.send_stream
                .send_message(session_token_msg.clone())
                .await?;

            let auth_response: AuthServerMessage = self.recv_stream.receive_message().await?;

            match auth_response {
                AuthServerMessage::Ok => {}
                _ => return Err(anyhow!("Session died")),
            }

            sleep(self.auth_interval).await;
        }
    }
}
