#![allow(async_fn_in_trait)]

use crate::network::packet::Packet;
use anyhow::Result;
use bytes::BytesMut;
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun2::{AsyncDevice, Configuration};

pub trait InterfaceRead: AsyncReadExt + Sized + Unpin + Send + 'static {
    #[inline]
    async fn read_packet(&mut self, buf_size: usize) -> Result<Packet> {
        let mut buf = BytesMut::with_capacity(buf_size);
        self.read_buf(&mut buf).await?;

        Ok(buf.into())
    }
}

pub trait InterfaceWrite: AsyncWriteExt + Sized + Unpin + Send + 'static {
    #[inline]
    async fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        self.write_all(&packet.data).await?;

        Ok(())
    }

    #[inline]
    async fn write_packets(&mut self, packets: &[Packet]) -> Result<()> {
        // TODO: Implement this using write_vectored when it actually works
        for packet in packets {
            self.write_packet(packet).await?;
        }

        Ok(())
    }
}

pub trait Interface: InterfaceRead + InterfaceWrite {
    fn create(interface_address: IpNet, mtu: u16) -> Result<Self>;

    fn split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

impl<I: Interface> InterfaceRead for ReadHalf<I> {}
impl<I: Interface> InterfaceWrite for WriteHalf<I> {}
impl InterfaceRead for AsyncDevice {}
impl InterfaceWrite for AsyncDevice {}
impl Interface for AsyncDevice {
    fn create(interface_address: IpNet, mtu: u16) -> Result<AsyncDevice> {
        let mut config = Configuration::default();

        config
            .address(interface_address.addr())
            .netmask(interface_address.netmask())
            .mtu(mtu)
            .up();

        // Needed due to rust-tun using the destination address as the default GW
        #[cfg(not(target_os = "windows"))]
        config.destination(interface_address.network());

        let interface = tun2::create_as_async(&config)?;

        Ok(interface)
    }
}
