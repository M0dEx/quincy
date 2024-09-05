#![allow(async_fn_in_trait)]

use crate::network::packet::Packet;
use crate::network::route::add_routes;
use anyhow::{Context, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun2::{AbstractDevice, AsyncDevice, Configuration};

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
    fn create_server(interface_address: IpNet, mtu: u16) -> Result<Self>;

    fn create_client(
        interface_address: IpNet,
        tunnel_gateway: IpAddr,
        mtu: u16,
        routes: &[IpNet],
        dns_servers: &[IpAddr],
    ) -> Result<Self>;

    fn name(&self) -> Result<String>;

    fn split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

impl<I: Interface> InterfaceRead for ReadHalf<I> {}
impl<I: Interface> InterfaceWrite for WriteHalf<I> {}
impl InterfaceRead for AsyncDevice {}
impl InterfaceWrite for AsyncDevice {}
impl Interface for AsyncDevice {
    fn create_server(interface_address: IpNet, mtu: u16) -> Result<Self> {
        let mut config = Configuration::default();

        config
            .address(interface_address.addr())
            .netmask(interface_address.netmask())
            .destination(interface_address.network())
            .mtu(mtu)
            .up();

        let interface = tun2::create_as_async(&config)?;

        Ok(interface)
    }

    fn create_client(
        interface_address: IpNet,
        tunnel_gateway: IpAddr,
        mtu: u16,
        routes: &[IpNet],
        dns_servers: &[IpAddr],
    ) -> Result<Self> {
        let mut config = Configuration::default();

        config
            .address(interface_address.addr())
            .netmask(interface_address.netmask())
            .mtu(mtu)
            .up();

        #[cfg(not(target_os = "windows"))]
        config.destination(tunnel_gateway);

        #[cfg(target_os = "windows")]
        config.platform_config(|platform| {
            platform.dns_servers(dns_servers);
        });

        let interface = tun2::create_as_async(&config)?;

        add_routes(routes, &tunnel_gateway, &interface.tun_name()?)?;

        #[cfg(not(target_os = "windows"))]
        if !dns_servers.is_empty() {
            use crate::network::dns::add_dns_servers;
            add_dns_servers(dns_servers, &interface.tun_name()?)?;
        }

        Ok(interface)
    }

    fn name(&self) -> Result<String> {
        self.tun_name().context("failed to retrieve interface name")
    }
}
