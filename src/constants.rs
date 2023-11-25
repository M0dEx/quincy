use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use quinn::Runtime;

/// Represents the grace interval to add to the auth_timeout variable used for timing out a connection.
pub const AUTH_TIMEOUT_GRACE: u64 = 5;

/// Represents the size of an `Ipv4Addr` address.
pub const IPV4_ADDR_SIZE: usize = std::mem::size_of::<Ipv4Addr>();

/// Represents the size of an `Ipv6Addr` address.
pub const IPV6_ADDR_SIZE: usize = std::mem::size_of::<Ipv6Addr>();

/// Represents the default MTU overhead for QUIC.
pub const QUIC_MTU_OVERHEAD: u16 = 42;

/// Represents the interval used by various cleanup tasks.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// Error message when authentication fails.
pub const AUTH_FAILED_MESSAGE: &str = "Authentication failed";

/// Error message when authentication times out.
pub const AUTH_TIMEOUT_MESSAGE: &str = "Authentication timed out";

/// Buffer size for authentication messages.
pub const AUTH_MESSAGE_BUFFER_SIZE: usize = 1024;

/// Represents the size of the packet info header on UNIX systems.
#[cfg(target_os = "macos")]
pub const DARWIN_PI_HEADER_LENGTH: usize = 4;

/// Represents MacOS packet info header for IPv4
#[cfg(target_os = "macos")]
pub const DARWIN_PI_HEADER_IPV4: [u8; 4] = [0_u8, 0_u8, 0_u8, libc::AF_INET as u8];

/// Represents MacOS packet info header for IPv6
#[cfg(target_os = "macos")]
pub const DARWIN_PI_HEADER_IPV6: [u8; 4] = [0_u8, 0_u8, 0_u8, libc::AF_INET6 as u8];

/// Represents the supported TLS cipher suites for Quincy.
pub static QUINCY_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

/// Represents the supported TLS protocol versions for Quincy.
pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Represents the supported TLS ALPN protocols for Quincy.
pub static TLS_ALPN_PROTOCOLS: Lazy<Vec<Vec<u8>>> = Lazy::new(|| vec![b"quincy".to_vec()]);

/// Represents the async runtime used by Quinn.
pub static QUINN_RUNTIME: Lazy<Arc<dyn Runtime>> = Lazy::new(|| Arc::new(quinn::TokioRuntime));
