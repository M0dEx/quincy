use crate::constants::BINCODE_CONFIG;
use anyhow::{anyhow, Context, Result};
use bincode::{Decode, Encode};
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::warn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

pub fn bind_socket(
    addr: SocketAddr,
    send_buffer_size: usize,
    recv_buffer_size: usize,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .context("create socket")?;

    if addr.is_ipv6() {
        socket.set_only_v6(false).context("set_only_v6")?;
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .context("binding endpoint")?;
    socket
        .set_send_buffer_size(send_buffer_size)
        .context("send buffer size")?;
    socket
        .set_recv_buffer_size(recv_buffer_size)
        .context("recv buffer size")?;

    let buf_size = socket.send_buffer_size().context("send buffer size")?;
    if buf_size < send_buffer_size {
        warn!(
            "Unable to set desired send buffer size. Desired: {}, Actual: {}",
            send_buffer_size, buf_size
        );
    }

    let buf_size = socket.recv_buffer_size().context("recv buffer size")?;
    if buf_size < recv_buffer_size {
        warn!(
            "Unable to set desired recv buffer size. Desired: {}, Actual: {}",
            recv_buffer_size, buf_size
        );
    }

    Ok(socket.into())
}

pub fn enable_tracing(log_level: &str) {
    let registry = tracing_subscriber::Registry::default();
    let fmt_layer = tracing_subscriber::fmt::Layer::new();
    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    let subscriber = registry.with(filter_layer).with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

pub fn encode_message<M: Encode>(message: M) -> Result<Bytes> {
    let bytes = bincode::encode_to_vec(message, *BINCODE_CONFIG)?;

    Ok(bytes.into())
}

pub fn decode_message<M: Decode>(data: Bytes) -> Result<M> {
    let (res, _) = bincode::decode_from_slice(&data, *BINCODE_CONFIG)?;

    Ok(res)
}

pub fn ip_addr_to_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().into(),
        IpAddr::V6(addr) => addr.octets().into(),
    }
}

pub fn ip_addr_from_bytes(bytes: &[u8]) -> Result<IpAddr> {
    if bytes.len() == size_of::<Ipv4Addr>() {
        let octets: [u8; 4] = bytes.try_into()?;
        Ok(octets.into())
    } else if bytes.len() == size_of::<Ipv6Addr>() {
        let octets: [u8; 16] = bytes.try_into()?;
        Ok(octets.into())
    } else {
        Err(anyhow!("Failed to parse IpAddr from bytes"))
    }
}
