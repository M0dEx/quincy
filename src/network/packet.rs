use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use etherparse::{NetHeaders, PacketHeaders};
use std::net::IpAddr;

/// Structure encapsulating a network packet (its data) with additional metadata parsed from the packet.
#[derive(Debug, Clone)]
pub struct Packet {
    pub data: Bytes,
}

impl Packet {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Returns the destination IP address of the packet.
    pub fn destination(&self) -> anyhow::Result<IpAddr> {
        let headers =
            PacketHeaders::from_ip_slice(&self.data).context("failed to parse IP packet")?;
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
        packet.data
    }
}
