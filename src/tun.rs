use std::net::Ipv4Addr;

use anyhow::{anyhow, Result};
use tokio_tun::{TunBuilder, Tun};

pub fn make_tun(name: String, local_addr: Ipv4Addr, remote_addr: Ipv4Addr, mtu: u32) -> Result<Tun> {
    let tun = TunBuilder::new()
        .name(&name)
        .tap(false)
        .packet_info(false)
        .mtu(mtu as i32)
        .up()
        .address(local_addr)
        .destination(remote_addr)
        .try_build()
        .map_err(|e| anyhow!("Failed to create a TUN interface: {e}"))?;

    Ok(tun)
}