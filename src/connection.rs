use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use quinn::Connection;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio_tun::Tun;
use tracing::info;

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
            info!(
                "Received {} bytes from {:?}",
                data.len(),
                connection.remote_address()
            );

            tun_queue.send(data.into())?;
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

    pub fn get_connection(&self) -> &Arc<Connection> {
        &self.connection
    }
}

pub async fn relay_packets(connection: Arc<Connection>, interface: Tun, mtu: usize) -> Result<()> {
    let (read, write) = tokio::io::split(interface);

    let (_, _) = futures_util::try_join!(
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
        info!(
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
    loop {
        let data = connection.read_datagram().await?;
        info!(
            "Received {} bytes from {:?}",
            data.len(),
            connection.remote_address()
        );

        // info!("Writing {} bytes of data to interface", data.len());
        write_interface.write_all(&data).await?;
    }
}
