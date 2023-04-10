use std::net::IpAddr;

use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use bytes::Bytes;

use crate::constants::{BINCODE_CONFIG, IPV4_ADDR_SIZE, IPV6_ADDR_SIZE};

/// Encodes a message using bincode.
///
/// ### Arguments
/// - `message` - the message to be encoded
///
/// ### Returns
/// - `Bytes` - the encoded message
#[inline]
pub fn encode_message<M: Encode>(message: M) -> Result<Bytes> {
    let bytes = bincode::encode_to_vec(message, *BINCODE_CONFIG)?;

    Ok(bytes.into())
}

/// Decodes a message using bincode.
///
/// ### Arguments
/// - `data` - the data to be decoded
///
/// ### Returns
/// - Type `M` - the decoded message
#[inline]
pub fn decode_message<M: Decode>(data: Bytes) -> Result<M> {
    let (res, _) = bincode::decode_from_slice(&data, *BINCODE_CONFIG)?;

    Ok(res)
}

/// Converts an `IpAddr` to its byte representation.
///
/// ### Arguments
/// - `addr` - the `IpAddr` to be converted
///
/// ### Returns
/// - `Vec<u8>` - the byte representation of the `IpAddr`
#[inline]
pub fn ip_addr_to_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().into(),
        IpAddr::V6(addr) => addr.octets().into(),
    }
}

/// Converts a byte representation of an `IpAddr` to an `IpAddr`.
///
/// ### Arguments
/// - `bytes` - the byte representation of the `IpAddr`
///
/// ### Returns
/// - `IpAddr` - the `IpAddr` parsed from its byte representation
#[inline]
pub fn ip_addr_from_bytes(bytes: &[u8]) -> Result<IpAddr> {
    if bytes.len() == IPV4_ADDR_SIZE {
        let octets: [u8; IPV4_ADDR_SIZE] = bytes.try_into()?;
        Ok(octets.into())
    } else if bytes.len() == IPV6_ADDR_SIZE {
        let octets: [u8; IPV6_ADDR_SIZE] = bytes.try_into()?;
        Ok(octets.into())
    } else {
        Err(anyhow!("Failed to parse IpAddr from bytes"))
    }
}
