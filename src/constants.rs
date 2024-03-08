use std::sync::Arc;

use once_cell::sync::Lazy;
use quinn::Runtime;

/// Represents the maximum MTU overhead for QUIC, since the QUIC header is variable in size.
pub const QUIC_MTU_OVERHEAD: u16 = 50;

/// Buffer size for authentication messages.
pub const AUTH_MESSAGE_BUFFER_SIZE: usize = 1024;

/// Packet buffer size for operations on the TUN interface.
pub const PACKET_BUFFER_SIZE: usize = 4;

/// Packet channel size used for communication between the TUN interface and QUIC tunnels.
pub const PACKET_CHANNEL_SIZE: usize = 1024 * 1024;

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
