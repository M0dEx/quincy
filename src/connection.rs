use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use delegate::delegate;
use quinn::Connection;
use quinn::SendDatagramError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio_tun::Tun;
use tracing::debug;

pub struct QuincyConnection {
    connection: Arc<Connection>,
    tun_queue: Arc<UnboundedSender<Bytes>>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl QuincyConnection {
    pub fn new(connection: Connection, tun_queue: Arc<UnboundedSender<Bytes>>) -> Self {
        Self {
            connection: Arc::new(connection),
            tun_queue,
            worker: None,
        }
    }

    async fn process_incoming_data(
        connection: Arc<Connection>,
        tun_queue: Arc<UnboundedSender<Bytes>>,
    ) -> Result<()> {
        loop {
            let data = connection.read_datagram().await?;
            debug!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            tun_queue.send(data)?;
        }
    }

    pub fn start_worker(&mut self) -> Result<()> {
        if self.worker.is_some() {
            return Err(anyhow!("There is already a worker active"));
        }

        let connection = self.connection.clone();
        let tun_queue = self.tun_queue.clone();

        self.worker = Some(tokio::spawn(Self::process_incoming_data(
            connection, tun_queue,
        )));

        Ok(())
    }

    delegate! {
        to self.connection {
            pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>;
            pub fn max_datagram_size(&self) -> Option<usize>;
            pub fn remote_address(&self) -> SocketAddr;
        }
    }
}

pub async fn relay_packets(connection: Arc<Connection>, interface: Tun, mtu: usize) -> Result<()> {
    let (read, write) = tokio::io::split(interface);

    let (_, _) = tokio::try_join!(
        tokio::spawn(handle_send(connection.clone(), read, mtu)),
        tokio::spawn(handle_recv(connection.clone(), write))
    )?;

    Ok(())
}

async fn handle_send(
    connection: Arc<Connection>,
    mut read_interface: ReadHalf<Tun>,
    interface_mtu: usize,
) -> Result<()> {
    debug!("Started send task");
    loop {
        let buf_size = connection.max_datagram_size().ok_or_else(|| {
            anyhow!("The other side of the connection is refusing to provide a max datagram size")
        })?;

        if interface_mtu > buf_size {
            return Err(anyhow!(
                "Interface MTU ({interface_mtu}) is higher than QUIC connection MTU ({buf_size})"
            ));
        }

        let mut buf = BytesMut::with_capacity(buf_size);
        read_interface.read_buf(&mut buf).await?;
        debug!(
            "Sending {} bytes to {:?}",
            buf.len(),
            connection.remote_address()
        );

        connection.send_datagram(buf.into())?;
    }
}

async fn handle_recv(
    connection: Arc<Connection>,
    mut write_interface: WriteHalf<Tun>,
) -> Result<()> {
    debug!("Started recv task");
    loop {
        let data = connection.read_datagram().await?;
        debug!(
            "Received {} bytes from {:?}",
            data.len(),
            connection.remote_address()
        );

        write_interface.write_all(&data).await?;
    }
}
