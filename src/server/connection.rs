use crate::auth::server::AuthServer;
use crate::auth::user::UserDatabase;
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;

use quinn::Connection;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, warn};

/// Represents a Quincy connection encapsulating authentication and IO.
#[derive(Clone)]
pub struct QuincyConnection {
    connection: Arc<Connection>,
    pub username: Option<String>,
    pub client_address: IpNet,
    ingress_queue: UnboundedSender<Bytes>,
}

impl QuincyConnection {
    /// Creates a new instance of the Quincy connection.
    ///
    /// ### Arguments
    /// - `connection` - the underlying QUIC connection
    /// - `tun_queue` - the queue to send data to the TUN interface
    /// - `user_database` - the user database
    /// - `auth_timeout` - the authentication timeout
    /// - `client_address` - the assigned client address
    pub fn new(
        connection: Arc<Connection>,
        client_address: IpNet,
        tun_queue: UnboundedSender<Bytes>,
    ) -> Self {
        Self {
            connection,
            username: None,
            client_address,
            ingress_queue: tun_queue,
        }
    }

    pub async fn authenticate(
        &mut self,
        user_database: &UserDatabase,
        connection_timeout: Duration,
    ) -> Result<()> {
        let auth_server = AuthServer::new(
            user_database,
            self.connection.clone(),
            self.client_address,
            connection_timeout,
        );

        let username = auth_server.handle_authentication().await?;

        info!(
            "Connection established: user = {}, client address = {}, remote address = {}",
            username,
            self.client_address.addr(),
            self.connection.remote_address().ip(),
        );

        self.username = Some(username);

        Ok(())
    }

    /// Starts the tasks for this instance of Quincy connection.
    pub async fn run(self, egress_queue: UnboundedReceiver<Bytes>) -> (Self, Error) {
        if self.username.is_none() {
            let client_address = self.client_address.addr();
            return (
                self,
                anyhow!("Client '{client_address}' is not authenticated"),
            );
        }

        let connection = Arc::new(self.clone());

        let outgoing_data_task =
            tokio::spawn(connection.clone().process_outgoing_data(egress_queue));
        let incoming_data_task = tokio::spawn(connection.clone().process_incoming_data());

        let err = tokio::select! {
            outgoing_data_err = outgoing_data_task => outgoing_data_err,
            incoming_data_err = incoming_data_task => incoming_data_err,
        }
        .expect("Joining tasks never fails")
        .expect_err("Connection tasks always return an error");

        (self, err)
    }

    async fn process_outgoing_data(
        self: Arc<Self>,
        mut egress_queue: UnboundedReceiver<Bytes>,
    ) -> Result<()> {
        loop {
            let data = egress_queue
                .recv()
                .await
                .ok_or_else(|| anyhow!("Egress queue has been closed"))?;

            let max_datagram_size = self.connection.max_datagram_size().ok_or_else(|| {
                anyhow!(
                    "Client {} failed to provide maximum datagram size",
                    self.connection.remote_address().ip()
                )
            })?;

            debug!("Maximum QUIC datagram size: {max_datagram_size}");

            if data.len() > max_datagram_size {
                warn!(
                    "Dropping packet of size {} due to maximum datagram size being {}",
                    data.len(),
                    max_datagram_size
                );
                continue;
            }

            debug!(
                "Sending {} bytes to {:?}",
                data.len(),
                self.client_address.addr()
            );

            self.connection.send_datagram(data)?;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    ///
    /// ### Arguments
    /// - `connection` - a reference to the underlying QUIC connection
    /// - `tun_queue` - a sender of an unbounded queue used by the tunnel worker to receive data
    async fn process_incoming_data(self: Arc<Self>) -> Result<()> {
        loop {
            let data = self.connection.read_datagram().await?;

            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                self.client_address.addr()
            );

            self.ingress_queue.send(data)?;
        }
    }
}
