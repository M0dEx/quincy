use std::net::SocketAddr;

use ::tracing::warn;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

/// Binds a UDP socket to the given address and sets the send and receive buffer sizes.
///
/// ### Arguments
/// - `addr` - the address to bind the socket to
/// - `send_buffer_size` - the size of the send buffer
/// - `recv_buffer_size` - the size of the receive buffer
///
/// ### Returns
/// - `std::net::UdpSocket` - the bound socket
pub fn bind_socket(
    addr: SocketAddr,
    send_buffer_size: usize,
    recv_buffer_size: usize,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket")?;

    if addr.is_ipv6() {
        socket
            .set_only_v6(false)
            .context("failed to make UDP socket dual-stack (not IPv6-only)")?;
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .context("failed to bind UDP socket")?;
    socket
        .set_send_buffer_size(send_buffer_size)
        .context(format!(
            "failed to set UDP socket send buffer size: {}",
            send_buffer_size
        ))?;
    socket
        .set_recv_buffer_size(recv_buffer_size)
        .context(format!(
            "failed to set UDP socket recv buffer size: {}",
            recv_buffer_size
        ))?;

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
