use anyhow::Result;
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::{AsyncDevice, Configuration};

pub fn set_up_interface(interface_address: IpNet, mtu: u32) -> Result<AsyncDevice> {
    let mut config = Configuration::default();

    config
        .address(interface_address.addr())
        .netmask(interface_address.netmask())
        .destination(interface_address.network())
        .mtu(mtu as i32)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(false);
    });

    let interface = tun::create_as_async(&config)?;

    Ok(interface)
}

#[inline]
pub async fn read_from_interface(
    interface: &mut ReadHalf<AsyncDevice>,
    buf_size: usize,
) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(buf_size);
    interface.read_buf(&mut buf).await?;

    #[cfg(target_os = "macos")]
    let data = truncate_packet_info_header(buf);

    #[cfg(not(target_os = "macos"))]
    let data = buf.into();

    Ok(data)
}

#[inline]
pub async fn write_to_interface(interface: &mut WriteHalf<AsyncDevice>, data: Bytes) -> Result<()> {
    #[cfg(target_os = "macos")]
    let packet_data = prepend_packet_info_header(data)?;

    #[cfg(not(target_os = "macos"))]
    let packet_data = data;

    interface.write_all(&packet_data).await?;

    Ok(())
}

#[cfg(target_os = "macos")]
#[inline]
fn prepend_packet_info_header(data: Bytes) -> Result<Bytes> {
    use crate::constants::PACKET_INFO_HEADER_SIZE;
    use anyhow::anyhow;
    use bytes::BufMut;
    use etherparse::IpHeader;
    use etherparse::PacketHeaders;

    let packet_headers = PacketHeaders::from_ip_slice(&data)?;
    let ip_header = packet_headers
        .ip
        .ok_or_else(|| anyhow!("Received packet with invalid IP header"))?;

    let mut packet_data = BytesMut::with_capacity(data.len() + PACKET_INFO_HEADER_SIZE);
    match ip_header {
        IpHeader::Version4(_, _) => packet_data.put_slice(&[0_u8, 0_u8, 0_u8, libc::AF_INET as u8]),
        IpHeader::Version6(_, _) => {
            packet_data.put_slice(&[0_u8, 0_u8, 0_u8, libc::AF_INET6 as u8])
        }
    };

    // TODO: Do not copy
    packet_data.put(data);
    Ok(packet_data.into())
}

#[cfg(target_os = "macos")]
#[inline]
fn truncate_packet_info_header(data: BytesMut) -> Bytes {
    use crate::constants::PACKET_INFO_HEADER_SIZE;

    Bytes::from(data).slice(PACKET_INFO_HEADER_SIZE..)
}
