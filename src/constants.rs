use bincode::config::{Configuration, Limit, LittleEndian, Varint};
use once_cell::sync::Lazy;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::Mutex;

pub const PACKET_INFO_HEADER_SIZE: usize = 4;
pub const BINCODE_BUFFER_SIZE: usize = 128;
pub const AUTH_TIMEOUT_GRACE: u64 = 5;

pub static BINCODE_CONFIG: Lazy<Configuration<LittleEndian, Varint, Limit<BINCODE_BUFFER_SIZE>>> =
    Lazy::new(|| bincode::config::standard().with_limit::<BINCODE_BUFFER_SIZE>());

pub static CPRNG: Lazy<Mutex<ChaCha20Rng>> = Lazy::new(|| Mutex::new(ChaCha20Rng::from_entropy()));

pub static QUINCY_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

pub static TLS_ALPN_PROTOCOLS: Lazy<Vec<Vec<u8>>> = Lazy::new(|| vec![b"quincy".to_vec()]);

pub const QUIC_MTU_OVERHEAD: u16 = 42;
