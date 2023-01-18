use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use tokio_tun::Tun;

pub async fn relay_packets(connection: Arc<quinn::Connection>, interface: Tun, mtu: usize) -> Result<()> {

    let (read, write) = tokio::io::split(interface);

    let (_, _) = futures_util::try_join!(
        tokio::spawn(handle_send(connection.clone(), read, mtu)),
        tokio::spawn(handle_recv(connection.clone(), write))
    )?;

    Ok(())
}

async fn handle_send(connection: Arc<quinn::Connection>, mut read_interface: ReadHalf<Tun>, interface_mtu: usize) -> Result<()> {
    loop {
        let buf_size = connection
            .max_datagram_size()
            .ok_or_else(|| anyhow!("The other side of the connection is refusing to provide a max datagram size"))?;

        if interface_mtu > buf_size {
            return Err(anyhow!("Interface MTU ({interface_mtu}) is higher than QUIC connection MTU ({buf_size})"))
        }

        let mut buf = BytesMut::with_capacity(buf_size);
        read_interface.read_buf(&mut buf).await?;
        // info!("Sending {} bytes through the tunnel", buf.len());

        connection.send_datagram(buf.into())?;
    }
}

async fn handle_recv(connection: Arc<quinn::Connection>, mut write_interface: WriteHalf<Tun>) -> Result<()> {
    loop {
        let data = connection.read_datagram().await?;

        // info!("Writing {} bytes of data to interface", data.len());
        write_interface.write_all(&data).await?;
    }
}
