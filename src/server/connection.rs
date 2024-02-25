use crate::auth::user::UserDatabase;
use crate::{auth::server::AuthServer, utils::tasks::abort_all};
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::IpNet;

use crate::server::address_pool::AddressPool;
use quinn::Connection;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, info};

/// Represents a Quincy connection encapsulating authentication and IO.
#[derive(Clone)]
pub struct QuincyConnection {
    connection: Arc<Connection>,
    username: Option<String>,
    client_address: Option<IpNet>,
    ingress_queue: UnboundedSender<Bytes>,
}

impl QuincyConnection {
    /// Creates a new instance of the Quincy connection.
    ///
    /// ### Arguments
    /// - `connection` - the underlying QUIC connection
    /// - `tun_queue` - the queue to send data to the TUN interface
    pub fn new(connection: Connection, tun_queue: UnboundedSender<Bytes>) -> Self {
        Self {
            connection: Arc::new(connection),
            username: None,
            client_address: None,
            ingress_queue: tun_queue,
        }
    }

    /// Attempts to authenticate the client.
    pub async fn authenticate(
        mut self,
        user_database: &UserDatabase,
        address_pool: &AddressPool,
        connection_timeout: Duration,
    ) -> Result<Self> {
        let auth_server = AuthServer::new(
            user_database,
            address_pool,
            self.connection.clone(),
            connection_timeout,
        );

        let (username, client_address) = auth_server.handle_authentication().await?;

        info!(
            "Connection established: user = {}, client address = {}, remote address = {}",
            username,
            client_address.addr(),
            self.connection.remote_address().ip(),
        );

        self.username = Some(username);
        self.client_address = Some(client_address);

        Ok(self)
    }

    /// Starts the tasks for this instance of Quincy connection.
    pub async fn run(self, egress_queue: UnboundedReceiver<Bytes>) -> (Self, Error) {
        if self.username.is_none() {
            let client_address = self.connection.remote_address();
            return (
                self,
                anyhow!("Client '{}' is not authenticated", client_address.ip()),
            );
        }

        let connection = Arc::new(self);

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(connection.clone().process_outgoing_data(egress_queue)),
            tokio::spawn(connection.clone().process_incoming_data()),
        ]);

        let res = tasks
            .next()
            .await
            .expect("tasks is not empty")
            .expect("task is joinable");

        let _ = abort_all(tasks).await;

        (
            Arc::into_inner(connection).expect("there is exactly one Arc instance at this point"),
            res.expect_err("task failed"),
        )
    }

    /// Processes outgoing data and sends it to the QUIC connection.
    ///
    /// ### Arguments
    /// - `egress_queue` - the queue to receive data from the TUN interface
    async fn process_outgoing_data(
        self: Arc<Self>,
        mut egress_queue: UnboundedReceiver<Bytes>,
    ) -> Result<()> {
        loop {
            let data = egress_queue
                .recv()
                .await
                .ok_or(anyhow!("Egress queue has been closed"))?;

            debug!(
                "Sending {} bytes to {:?}",
                data.len(),
                self.client_address()?.addr()
            );

            self.connection.send_datagram(data)?;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    async fn process_incoming_data(self: Arc<Self>) -> Result<()> {
        loop {
            let data = self.connection.read_datagram().await?;

            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                self.client_address()?.addr()
            );

            self.ingress_queue.send(data)?;
        }
    }

    /// Returns the username associated with this connection.
    #[allow(dead_code)]
    pub fn username(&self) -> Result<&str> {
        self.username
            .as_deref()
            .ok_or(anyhow!("Connection is unauthenticated"))
    }

    /// Returns the client address associated with this connection.
    pub fn client_address(&self) -> Result<&IpNet> {
        self.client_address
            .as_ref()
            .ok_or(anyhow!("Connection is unauthenticated"))
    }
}
