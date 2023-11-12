use anyhow::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::{AsyncDevice, Configuration};

#[async_trait]
pub trait InterfaceRead: AsyncReadExt + Sized + Unpin + Sync + Send + 'static {
    #[inline]
    async fn read_packet(&mut self, buf_size: usize) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(buf_size);
        self.read_buf(&mut buf).await?;

        #[cfg(target_os = "macos")]
        let data = truncate_packet_info_header(buf.into());

        #[cfg(not(target_os = "macos"))]
        let data = buf.into();

        Ok(data)
    }
}

#[async_trait]
pub trait InterfaceWrite: AsyncWriteExt + Sized + Unpin + Sync + Send + 'static {
    #[inline]
    async fn write_packet(&mut self, packet_data: Bytes) -> Result<()> {
        #[cfg(target_os = "macos")]
        let packet_data = prepend_packet_info_header(packet_data)?;

        #[cfg(not(target_os = "macos"))]
        let packet_data = packet_data;

        self.write_all(&packet_data).await?;

        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[inline]
pub fn truncate_packet_info_header(data: Bytes) -> Bytes {
    use crate::constants::DARWIN_PI_HEADER_LENGTH;
    data.slice(DARWIN_PI_HEADER_LENGTH..)
}

#[cfg(target_os = "macos")]
#[inline]
pub fn prepend_packet_info_header(data: Bytes) -> Result<Bytes> {
    use crate::constants::DARWIN_PI_HEADER_IPV4;
    use crate::constants::DARWIN_PI_HEADER_IPV6;
    use anyhow::anyhow;
    use etherparse::IpHeader;
    use etherparse::PacketHeaders;

    let packet_headers = PacketHeaders::from_ip_slice(&data)?;
    let ip_header = packet_headers
        .ip
        .ok_or_else(|| anyhow!("Received packet with invalid IP header"))?;

    let pi_header = match ip_header {
        IpHeader::Version4(_, _) => Bytes::from_static(DARWIN_PI_HEADER_IPV4.as_ref()),
        IpHeader::Version6(_, _) => Bytes::from_static(DARWIN_PI_HEADER_IPV6.as_ref()),
    };

    // TODO: Do not copy
    Ok([pi_header.as_ref(), data.as_ref()].concat().into())
}

pub trait Interface: InterfaceRead + InterfaceWrite {
    fn create(interface_address: IpNet, mtu: i32) -> Result<Self>;
}

impl<I: Interface> InterfaceRead for ReadHalf<I> {}
impl<I: Interface> InterfaceWrite for WriteHalf<I> {}
impl InterfaceRead for AsyncDevice {}
impl InterfaceWrite for AsyncDevice {}
impl Interface for AsyncDevice {
    fn create(interface_address: IpNet, mtu: i32) -> Result<AsyncDevice> {
        let mut config = Configuration::default();

        config
            .address(interface_address.addr())
            .netmask(interface_address.netmask())
            .mtu(mtu)
            .up();

        // Needed due to rust-tun using the destination address as the default GW
        #[cfg(not(target_os = "windows"))]
        config.destination(interface_address.network());

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let interface = tun::create_as_async(&config)?;

        Ok(interface)
    }
}
