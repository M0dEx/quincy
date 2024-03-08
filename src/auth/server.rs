use std::{sync::Arc, time::Duration};

use crate::{
    config::{AuthType, ServerAuthenticationConfig},
    server::address_pool::AddressPool,
};
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use quinn::Connection;
use tokio::time::timeout;

use super::{
    stream::{AuthMessage, AuthStreamBuilder, AuthStreamMode},
    users_file::UsersFileServerAuthenticator,
    ServerAuthenticator,
};

/// Represents an authentication server handling initial authentication and session management.
pub struct AuthServer {
    authenticator: Box<dyn ServerAuthenticator>,
    address_pool: Arc<AddressPool>,
    auth_timeout: Duration,
}

impl AuthServer {
    pub fn new(
        config: ServerAuthenticationConfig,
        address_pool: Arc<AddressPool>,
        auth_timeout: Duration,
    ) -> Result<Self> {
        let authenticator = match config.auth_type {
            AuthType::UsersFile => UsersFileServerAuthenticator::new(&config)?,
        };

        Ok(Self {
            authenticator: Box::new(authenticator),
            address_pool,
            auth_timeout,
        })
    }

    /// Handles authentication for a client.
    ///
    /// ### Arguments
    /// - `connection` - The connection to the client
    pub async fn handle_authentication(&self, connection: &Connection) -> Result<(String, IpNet)> {
        let auth_stream_builder = AuthStreamBuilder::new(AuthStreamMode::Server);
        let mut auth_stream = auth_stream_builder
            .connect(connection, self.auth_timeout)
            .await?;

        let message = timeout(self.auth_timeout, auth_stream.recv_message()).await??;

        match message {
            AuthMessage::Authenticate(payload) => {
                let (username, address) = self
                    .authenticator
                    .authenticate_user(&self.address_pool, payload)
                    .await?;

                auth_stream
                    .send_message(AuthMessage::Authenticated(
                        address.addr(),
                        address.netmask(),
                    ))
                    .await?;

                Ok((username, address))
            }
            _ => Err(anyhow!("authentication failed")),
        }
    }
}
