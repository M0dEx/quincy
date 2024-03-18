#![allow(async_fn_in_trait)]
use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use etherparse::{NetHeaders, PacketHeaders};
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
        self.write_all(&packet.0).await?;

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

#[derive(Debug, Clone)]
pub struct Packet(Bytes);

impl Packet {
    pub fn new(data: Bytes) -> Self {
        Self(data)
    }

    pub fn destination(&self) -> Result<IpAddr> {
        let headers = PacketHeaders::from_ip_slice(&self.0).context("failed to parse IP packet")?;
        let net_header = headers.net.ok_or(anyhow!("no network header"))?;

        match net_header {
            NetHeaders::Ipv4(header, _) => Ok(header.destination.into()),
            NetHeaders::Ipv6(header, _) => Ok(header.destination.into()),
        }
    }
}

impl From<BytesMut> for Packet {
    fn from(data: BytesMut) -> Self {
        Self::new(data.freeze())
    }
}

impl From<Bytes> for Packet {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}

impl From<Packet> for Bytes {
    fn from(packet: Packet) -> Self {
        packet.0
    }
}
