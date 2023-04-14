use anyhow::Result;
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::{AsyncDevice, Configuration};

/// Sets up a new TUN interface.
///
/// ### Arguments
/// - `interface_address` - an address and network mask to be used by the interface
/// - `mtu` - the MTU of the interface
///
/// ### Returns
/// - `AsyncDevice` - the TUN interface
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

/// Reads a packet from the TUN interface.
///
/// ### Arguments
/// - `interface` - a read half of the TUN interface
/// - `buf_size` - the size of the buffer to be used for reading from the TUN interface
///
/// ### Returns
/// - `Bytes` - the packet read from the TUN interface
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

/// Writes a packet to the TUN interface.
///
/// ### Arguments
/// - `interface` - a write half of the TUN interface
/// - `data` - the packet to be written to the TUN interface
#[inline]
pub async fn write_to_interface(interface: &mut WriteHalf<AsyncDevice>, data: Bytes) -> Result<()> {
    #[cfg(target_os = "macos")]
    let packet_data = prepend_packet_info_header(data)?;

    #[cfg(not(target_os = "macos"))]
    let packet_data = data;

    interface.write_all(&packet_data).await?;

    Ok(())
}

/// Prepends the packet info header to the packet.
///
/// ### Arguments
/// - `data` - the packet to be prepended
///
/// ### Returns
/// - `Bytes` - the prepended packet
#[cfg(target_os = "macos")]
#[inline]
fn prepend_packet_info_header(data: Bytes) -> Result<Bytes> {
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

/// Truncates the packet info header from the packet.
///
/// ### Arguments
/// - `data` - the packet to be truncated
///
/// ### Returns
/// - `Bytes` - the truncated packet
#[cfg(target_os = "macos")]
#[inline]
fn truncate_packet_info_header(data: BytesMut) -> Bytes {
    use crate::constants::DARWIN_PI_HEADER_LENGTH;

    Bytes::from(data).slice(DARWIN_PI_HEADER_LENGTH..)
}
