use once_cell::sync::Lazy;

pub static QUINCY_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

pub static TLS_ALPN_PROTOCOLS: Lazy<Vec<Vec<u8>>> = Lazy::new(|| vec![b"quincy".to_vec()]);

pub static QUIC_MTU_OVERHEAD: u16 = 42;
