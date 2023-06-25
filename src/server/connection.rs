use crate::auth::server::{AuthServer, AuthState};
use crate::auth::user::UserDatabase;
use crate::constants::AUTH_TIMEOUT_GRACE;
use crate::utils::tasks::join_or_abort_task;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use delegate::delegate;
use ipnet::IpNet;

use quinn::Connection;
use quinn::SendDatagramError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::log::warn;
use tracing::{debug, error};

/// Represents a Quincy connection encapsulating authentication and IO.
pub struct QuincyConnection {
    connection: Arc<Connection>,
    auth_server: Arc<RwLock<AuthServer>>,
    tun_queue: Arc<UnboundedSender<Bytes>>,
    tasks: Vec<JoinHandle<Result<()>>>,
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
    pub async fn new(
        connection: Connection,
        tun_queue: Arc<UnboundedSender<Bytes>>,
        user_database: Arc<UserDatabase>,
        auth_timeout: u32,
        client_address: IpNet,
    ) -> Result<Self> {
        let connection = Arc::new(connection);
        let auth_timeout = Duration::from_secs(auth_timeout as u64 + AUTH_TIMEOUT_GRACE);
        let auth_server = AuthServer::new(
            user_database,
            connection.clone(),
            client_address,
            auth_timeout,
        )
        .await?;

        Ok(Self {
            connection,
            auth_server: Arc::new(RwLock::new(auth_server)),
            tun_queue,
            tasks: Vec::new(),
        })
    }

    /// Starts the tasks for this instance of Quincy connection.
    pub async fn start(&mut self) -> Result<()> {
        if self.is_ok() {
            return Err(anyhow!(
                "This instance of Quincy connection is already running"
            ));
        }

        self.tasks.push(tokio::spawn(Self::handle_authentication(
            self.auth_server.clone(),
        )));

        self.tasks.push(tokio::spawn(Self::process_incoming_data(
            self.connection.clone(),
            self.tun_queue.clone(),
            self.auth_server.clone(),
        )));

        Ok(())
    }

    /// Stops the tasks for this instance of Quincy connection.
    pub async fn stop(&mut self) -> Result<()> {
        let timeout = Duration::from_secs(1);

        while let Some(task) = self.tasks.pop() {
            if let Some(Err(e)) = join_or_abort_task(task, timeout).await {
                error!("An error occurred in Quincy connection: {e}")
            }
        }

        Ok(())
    }

    /// Checks whether this instance of Quincy connection is running.
    ///
    /// ### Returns
    /// - `true` if all connection tasks are running, `false` if not
    pub fn is_ok(&self) -> bool {
        !self.tasks.is_empty() && self.tasks.iter().all(|task| !task.is_finished())
    }

    /// Sends an unreliable datagram to the client.
    ///
    /// ### Arguments
    /// - `data` - the data to be sent
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        match self.auth_server.read().await.get_state().await {
            AuthState::Authenticated(_) => (),
            _ => {
                warn!(
                    "Connection {:?} not authenticated, dropping outgoing data",
                    self.connection.remote_address(),
                );
                return Ok(());
            }
        }

        self.connection.send_datagram(data)?;

        Ok(())
    }

    delegate! {
        to self.connection {
            pub fn max_datagram_size(&self) -> Option<usize>;
            pub fn remote_address(&self) -> SocketAddr;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    ///
    /// ### Arguments
    /// - `connection` - a reference to the underlying QUIC connection
    /// - `tun_queue` - a sender of an unbounded queue used by the tunnel worker to receive data
    async fn process_incoming_data(
        connection: Arc<Connection>,
        tun_queue: Arc<UnboundedSender<Bytes>>,
        auth_server: Arc<RwLock<AuthServer>>,
    ) -> Result<()> {
        loop {
            match auth_server.read().await.get_state().await {
                AuthState::Authenticated(_) => (),
                _ => {
                    warn!(
                        "Connection {:?} not authenticated, dropping incoming data",
                        connection.remote_address(),
                    );
                    continue;
                }
            }

            let data = connection.read_datagram().await?;
            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            tun_queue.send(data)?;
        }
    }

    async fn handle_authentication(auth_server: Arc<RwLock<AuthServer>>) -> Result<()> {
        let auth_server = auth_server.read().await;
        auth_server.handle_authentication().await
    }
}
