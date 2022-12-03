use std::sync::Arc;
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::info;

pub async fn relay_packets(connection: Arc<quinn::Connection>, interface: tokio_tun::Tun) -> Result<()> {

    let interface_mtu = interface.mtu().unwrap() as usize;
    let (read, write) = tokio::io::split(interface);

    let (_, _) = futures_util::try_join!(
        tokio::spawn(handle_send(connection.clone(), read, interface_mtu)),
        tokio::spawn(handle_recv(connection.clone(), write))
    )?;

    Ok(())
}

async fn handle_send(connection: Arc<quinn::Connection>, mut read_interface: ReadHalf<tokio_tun::Tun>, interface_mtu: usize) -> Result<()> {
    loop {
        let buf_size = connection
            .max_datagram_size()
            .ok_or(
                anyhow!("The other send of the connection is refusing to provide a max datagram size")
            )?;

        if interface_mtu > buf_size {
            return Err(anyhow!("Interface MTU ({interface_mtu}) is higher than QUIC connection MTU ({buf_size})"))
        }

        let mut buf = BytesMut::with_capacity(buf_size);
        let size = read_interface.read_buf(&mut buf).await?;

        connection.send_datagram(buf.to_vec().into())?;
    }
}

async fn handle_recv(connection: Arc<quinn::Connection>, mut write_interface: WriteHalf<tokio_tun::Tun>) -> Result<()> {
    loop {
        let data = connection.read_datagram().await?;
        write_interface.write_all(&data).await?;
    }
}
